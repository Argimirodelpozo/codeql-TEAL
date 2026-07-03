"""AVM type / phi recovery for the lift (see :mod:`lift`).

After :class:`lift._Lifter` builds the IR, some registers are still ``?`` (params
/ returns crossing subroutines, scratch loads, state reads, placeholder phi webs).
:func:`recover_types` closes them with a monotonic per-sub fixpoint;
:func:`finalize_types` reconciles mixed-type phi webs on the assembled program.
Both read the lifter's maps via a duck-typed ``lifter`` (never imports lift).
"""
from __future__ import annotations

import logging

from ..ssa import Const, Phi, SSAVar
from . import pre_ir
from .optypes import (_BYTES_CONSUME, _BYTES_OPS, _U64_CONSUME, _U64_OPS,
                      _field_type, _imm0, avm)
from .teal_const import _const_bytes

logger = logging.getLogger("tealql.tealtools.lift")


def _empty_bytes(b) -> bool:
    """True if a BytesConstant is the empty-bytes placeholder (`""` / `0x`)."""
    v = (getattr(b, "value", "") or "").strip()
    return v in ("", "0x", '""', "''")


def _itxn_field_avm(field: str):
    """The AVM type ('b'/'u') a given `itxn_field <Field>` operand must be, from
    Puya's own transaction-field registry (OnCompletion -> uint64, Note -> bytes,
    Receiver -> account/bytes, ...). None for an unknown field."""
    try:
        from puya.awst.txn_fields import TxnField
        w = str(getattr(TxnField[field], "wtype", "")).lower()
    except (ImportError, AttributeError, KeyError) as e:
        # ImportError: puya moved the registry; KeyError: unknown field name
        # (the documented None case); AttributeError: enum-member API change.
        logger.debug("itxn-field typing unavailable for %r: %s", field, e)
        return None
    if "byte" in w or "account" in w or "string" in w:
        return "b"
    if "uint64" in w or "bool" in w or "asset" in w or "application" in w:
        return "u"
    return None


def _itob_const(v: int) -> "pre_ir.BytesConstant":
    """A uint64 placeholder rewritten to bytes: empty for the (dead) 0 seed
    that a `bytes` accumulator slot is initialised with, else its itob form."""
    return pre_ir.BytesConstant("0x" if v == 0 else "0x" + v.to_bytes(8, "big").hex())


def _to_u64_const(b) -> "pre_ir.UInt64Constant":
    """A bytes placeholder rewritten to uint64 (the symmetric case: a uint64
    slot seeded with empty `""`/`0x`); empty -> 0, else its btoi value."""
    try:
        raw, _ = _const_bytes(getattr(b, "value", "") or "0x")
        return pre_ir.UInt64Constant(int.from_bytes(raw[-8:], "big") if raw else 0)
    except Exception:
        return pre_ir.UInt64Constant(0)


def _const_key(operand) -> "str | None":
    """The constant bytes value of a state-key operand (verbatim ``0x…`` hex),
    or ``None`` if the key isn't a static constant (a dynamic key can't be
    matched across put / get)."""
    if isinstance(operand, Const):
        return operand.value if operand.kind == "bytes" else None
    cv = getattr(operand, "const_value", None)
    if cv is not None and getattr(cv, "kind", None) == "bytes":
        return cv.value
    return None


_BYTES_FAMILY = frozenset({"bytes", "account"})


_U64_FAMILY = frozenset({"uint64", "bool", "asset", "application"})


def _avm_join(types) -> str | None:
    """Common AVM type of a set of lift type strings, or None if they cross the
    uint64/bytes divide. Puya phis/assignments check the *AVM* type, so an
    `account` and a `bytes` unify to `bytes`, `bool` and `uint64` to `uint64`."""
    ts = {t for t in types if t and t != "?"}
    if not ts:
        return None
    if len(ts) == 1:
        return next(iter(ts))
    if ts <= _BYTES_FAMILY:
        return "bytes"
    if ts <= _U64_FAMILY:
        return "uint64"
    return None


# Ops whose stack inputs are all uint64 / all bytes.
_U64_IN_ALL = frozenset({
    "+", "-", "*", "/", "%", "exp", "expw", "addw", "mulw", "divw", "divmodw",
    "sqrt", "shl", "shr", "bitlen", "<", ">", "<=", ">=", "!", "&&", "||",
    "itob", "assert",
})


_BYTES_IN_ALL = frozenset({
    "concat", "len", "btoi", "sha256", "sha512_256", "keccak256", "sha3_256",
    "bsqrt", "b+", "b-", "b*", "b/", "b%", "b|", "b&", "b^", "b~",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
})


# Position-specific input types, indexed by SSA arg position which is
# **top-first** (inputs[0] is the topmost popped value). So for a TEAL op
# documented ``op A B C`` (A deepest, C on top) the SSA args are [C, B, A].
# ``None`` = leave the value unknown.
_POS_IN = {
    "getbyte": ("uint64", "bytes"),               # A(bytes) B(idx) -> [B, A]
    # getbit is POLYMORPHIC (value operand A is uint64 OR a byteslice) -- forcing `bytes`
    # mis-types a uint64 BITMAP (a u64 slot read by getbit), conflicts with the u64 store of the
    # same scratch slot -> spurious `poly` slot -> byteslice-mode getbit -> vacuous path. Leave A
    # unknown so the VALUE FLOW types it (u64 source -> u64; digest -> bytes); index B is uint64.
    "getbit": ("uint64", None),
    "setbyte": ("uint64", "uint64", "bytes"),     # A(bytes) B(idx) C(val)
    "extract3": ("uint64", "uint64", "bytes"),    # A(bytes) B(start) C(len)
    "substring3": ("uint64", "uint64", "bytes"),
    "extract_uint16": ("uint64", "bytes"),        # A(bytes) B(offset)
    "extract_uint32": ("uint64", "bytes"),
    "extract_uint64": ("uint64", "bytes"),
    "replace3": ("bytes", "uint64", "bytes"),     # A(bytes) B(start) C(bytes)
    "extract": ("bytes",),                        # extract s l A(bytes)
    "replace2": ("bytes", "bytes"),               # replace2 s A B -> [B, A] both bytes
    "app_global_get": ("bytes",),                 # key
    "app_global_put": (None, "bytes"),            # K(key) V(val) -> [V, K]
    "app_global_get_ex": ("bytes", "uint64"),     # app key -> [key, app]
    # local-state ops mirror the global ones plus the DEEPEST account operand.
    # Without these the key (and account) positions stay `?` and lower to uint64
    # -> app_local_get(uint64,uint64) mixed-type encode error. Source order is
    # (account, [app,] key[, value]); SSA is top-first (reversed), key shallowest.
    "app_local_get": ("bytes", None),            # acct key -> [key, acct]
    "app_local_put": (None, "bytes", None),      # acct key val -> [val, key, acct]
    "app_local_get_ex": ("bytes", "uint64", None),  # acct app key -> [key, app, acct]
    # the `del` siblings carry a bytes key too — same gap, same byteslice-key
    # lowering error if the key reaches them only through an untyped frame/phi.
    "app_global_del": ("bytes",),                # key
    "app_local_del": ("bytes", None),            # acct key -> [key, acct]
    "bzero": ("uint64",), "txnas": ("uint64",), "gtxnas": ("uint64",),
    # box ops: the NAME is the deepest operand (= last, top-first), always
    # bytes. Without this a box name reaching box_get only through a stack
    # frame slot (`bury N; ... frame_dig N; box_get`, the BoxMap `key in map`
    # membership+read pattern) stays `?` and lowers to uint64 -> mixed-type
    # encode error. Position-precise, so the u64 start/len/size operands stay
    # uint64, and the unanimity guard leaves a genuinely-mixed register `?`.
    "box_get": ("bytes",), "box_len": ("bytes",), "box_del": ("bytes",),
    "box_create": ("uint64", "bytes"),            # name size -> [size, name]
    "box_resize": ("uint64", "bytes"),
    "box_put": ("bytes", "bytes"),                # name value -> [value, name]
    "box_extract": ("uint64", "uint64", "bytes"), # name start len
    "box_replace": ("bytes", "uint64", "bytes"),  # name start value
    "box_splice": ("bytes", "uint64", "uint64", "bytes"),  # name start len value
}


def _expected_type(op, idx, args, imm=None):
    """Expected ``ir_type`` of ``args[idx]`` for ``op``, or ``None``."""
    if op in ("__cond__", "__exit__"):
        return "uint64"
    if op == "itxn_field" and idx == 0 and imm:
        # The single operand of `itxn_field <Field>` must be the field's AVM
        # type (Sender/Receiver/... -> bytes, Amount/Fee/... -> uint64). Without
        # this a non-phi value feeding an address field stays `?` and lowering
        # defaults it to uint64, which Puya's backend then rejects.
        a = _itxn_field_avm(str(imm[0]).strip())
        return "bytes" if a == "b" else "uint64" if a == "u" else None
    if op in _U64_IN_ALL:
        return "uint64"
    if op in _BYTES_IN_ALL:
        return "bytes"
    pos = _POS_IN.get(op)
    if pos and idx < len(pos):
        return pos[idx]
    if op in ("==", "!=") and len(args) == 2:
        other = args[1 - idx]
        ot = getattr(other, "ir_type", None)
        return ot if ot and ot != "?" else None
    return None


def _infer_types_from_uses(subs) -> None:
    """Refine ``?``-typed registers (params, locals, …) from the ops that
    consume them: arithmetic/cmp inputs are uint64, bytes-op inputs are bytes,
    ``==`` matches the other operand, branch conditions are uint64."""
    reg_by_id: dict = {}
    uses: dict = {}

    def use(r, op, idx, args, imm=None):
        if isinstance(r, pre_ir.Register):
            reg_by_id[id(r)] = r
            uses.setdefault(id(r), []).append((op, idx, args, imm))

    def note(vp):
        if isinstance(vp, (pre_ir.Intrinsic, pre_ir.InvokeSubroutine)):
            op = vp.op if isinstance(vp, pre_ir.Intrinsic) else None
            imm = vp.immediates if isinstance(vp, pre_ir.Intrinsic) else None
            for i, a in enumerate(vp.args):
                use(a, op, i, vp.args, imm)

    for b in pre_ir.blocks(subs):
        for o in b.ops:
            if isinstance(o, pre_ir.Assignment):
                note(o.source)
            elif isinstance(o, pre_ir.IntrinsicOp):
                note(o.intrinsic)
            elif isinstance(o, pre_ir.Assert):
                use(o.condition, "assert", 0, [o.condition])
        t = b.terminator
        if isinstance(t, pre_ir.ConditionalBranch):
            use(t.condition, "__cond__", 0, [t.condition])
        elif isinstance(t, pre_ir.ProgramExit):
            # `return` (and fall-off-end) pop a uint64 success value, so the
            # exit operand pins its producer to uint64. This is the only typing
            # signal for a program whose returned value comes from an otherwise
            # unconstrained source -- e.g. `gloads`/`gloadss` reading another
            # group txn's scratch (statically unknowable) feeding `return`.
            use(t.result, "__exit__", 0, [t.result])

    # Monotonic (only `?` -> a concrete type, guarded by `!= "?"`), so loop to
    # the fixpoint: guaranteed to terminate, with no depth cap to truncate a
    # long use-chain.
    changed = True
    while changed:
        changed = False
        for rid, r in reg_by_id.items():
            if r.ir_type != "?":
                continue
            inferred = {et for (op, i, args, imm) in uses.get(rid, [])
                        if (et := _expected_type(op, i, args, imm)) and et != "?"}
            if len(inferred) == 1:        # all uses agree -> safe to set
                r.ir_type = next(iter(inferred))
                changed = True


def _infer_returns(subs) -> None:
    """Set each subroutine's return types from its ``SubroutineReturn`` values
    (first typed value per position, across return sites)."""
    for sub in subs:
        if sub.is_main:
            continue
        rets = None
        for b in sub.body:
            t = b.terminator
            if isinstance(t, pre_ir.SubroutineReturn):
                ts = [getattr(v, "ir_type", "?") for v in t.result]
                if rets is None:
                    rets = ts
                else:
                    rets = [a if a != "?" else b2 for a, b2 in zip(rets, ts)]
        if rets is not None:
            # monotonic: keep any return position already typed (e.g. pinned by
            # inter-procedural unification from a caller), only fill the `?` ones.
            old = sub.returns
            sub.returns = [o if o != "?" else n
                           for o, n in zip(old, rets)] if len(old) == len(rets) \
                else rets


def _unify_phi_types(subs) -> None:
    # A phi merges one logical value, so its register and every arg share an AVM
    # type. Propagate BOTH ways: args -> register (joined to their common AVM
    # type) and register -> any still-`?` arg. Monotonic (only `?` -> concrete),
    # so the fixpoint terminates and no phi web is left half-typed.
    changed = True
    while changed:
        changed = False
        for b in pre_ir.blocks(subs):
            for phi in b.phis:
                rt = phi.register.ir_type
                if rt == "?":
                    j = _avm_join(getattr(a.value, "ir_type", "?")
                                  for a in phi.args)
                    if j is not None:
                        phi.register.ir_type = rt = j
                        changed = True
                if rt != "?":
                    for a in phi.args:
                        if getattr(a.value, "ir_type", None) == "?":
                            a.value.ir_type = rt
                            changed = True


def _reg_args(x):
    """Every Register reachable through an operand's `args` / `values`."""
    out = []
    if isinstance(x, pre_ir.Register):
        out.append(x)
    for a in (getattr(x, "args", None) or []) + (getattr(x, "values", None) or []):
        out += _reg_args(a)
    return out


def _collect_phi_evidence(blocks, find, phi_ids, parent):
    """Aggregate per-web type evidence in priority tiers. A phi-web's type is
    decided by, in order: how its values are *consumed* (strongest -- the seed of
    a wrong type is dead and can't be consumed as that type anyway), then a
    non-placeholder constant arg, then a non-phi member's own def type. Returns
    `(consumer, constev, defev)`, each `web-root -> {"u"|"b"}`."""
    from collections import defaultdict
    consumer: dict = defaultdict(set)
    constev: dict = defaultdict(set)
    defev: dict = defaultdict(set)
    for bb in blocks:
        for ph in bb.phis:
            root = find(id(ph.register))
            for a in ph.args:            # non-placeholder consts are real data
                v = a.value              # (empty bytes / uint64 0 are dead seeds)
                if isinstance(v, pre_ir.UInt64Constant) and v.value != 0:
                    constev[root].add("u")
                elif isinstance(v, pre_ir.BytesConstant) and not _empty_bytes(v):
                    constev[root].add("b")
        for o in bb.ops:
            if isinstance(o, pre_ir.Assignment) and not isinstance(o.source, pre_ir.Phi):
                for t in o.targets:
                    if id(t) in parent and id(t) not in phi_ids and avm(t.ir_type) != "?":
                        defev[find(id(t))].add(avm(t.ir_type))
            # Consumer evidence counts only *phi* registers (the accumulator
            # values): a seed register's own uses elsewhere (e.g. NumAppArgs in
            # routing) say nothing about the accumulator phi it merely seeds.
            src = getattr(o, "source", None) or getattr(o, "intrinsic", None)
            if isinstance(src, pre_ir.Intrinsic):
                k = ("u" if src.op in _U64_CONSUME
                     else "b" if src.op in _BYTES_CONSUME else None)
                if k is None and src.op == "itxn_field" and src.immediates:
                    k = _itxn_field_avm(str(src.immediates[0]).strip())
                if k:
                    for r in _reg_args(src):
                        if id(r) in phi_ids:
                            consumer[find(id(r))].add(k)
            if isinstance(o, pre_ir.Assert):
                for r in _reg_args(o.condition):
                    if id(r) in phi_ids:
                        consumer[find(id(r))].add("u")
    return consumer, constev, defev


def _decide_webtypes(phi_ids, find, consumer, constev, defev) -> dict:
    """Pick each web's type (`'bytes'`/`'uint64'`) from the first tier with a
    unanimous vote; a web with no real evidence at any tier is a dead-placeholder
    web -> collapse to uint64."""
    webtype: dict = {}                   # web root -> 'bytes' / 'uint64'
    for root in {find(rid) for rid in phi_ids}:
        for tier in (consumer, constev, defev):
            ev = tier.get(root, set())
            if len(ev) == 1:             # unanimous at this tier decides it
                webtype[root] = "bytes" if "b" in ev else "uint64"
                break
        else:
            # No real evidence at ANY tier -> a DEAD-placeholder web: every const
            # arg is a zero / empty `""` coarse-SSA seed (real consts/defs are what
            # the tiers count, and all were excluded) and no op consumes it as a
            # type. Such a web merges differently-typed dead seeds (e.g. uint64 0
            # with empty bytes) and Puya rejects the cross-type phi -- but the value
            # is never used, so collapse it to one family. uint64 = the lowering
            # default; the bytes seeds then coerce to uint64 0 below. (A web with
            # any REAL evidence is left for the encoder to flag as a true conflict.)
            if not (consumer.get(root) or constev.get(root) or defev.get(root)):
                webtype[root] = "uint64"
    return webtype


def _apply_webtypes(blocks, find, phi_ids, webtype) -> None:
    """Retype every phi-register web member to its decided type and coerce
    wrong-AVM-type args (const -> the other family's const; a cross-type non-phi
    seed register -> a dead placeholder)."""
    def placeholder(T):
        return _itob_const(0) if T == "bytes" else pre_ir.UInt64Constant(0)

    for bb in blocks:                    # retype every phi-register member
        for ph in bb.phis:
            T = webtype.get(find(id(ph.register)))
            if T:
                ph.register.ir_type = T
    for bb in blocks:                    # coerce args of the wrong AVM type
        for ph in bb.phis:
            T = webtype.get(find(id(ph.register)))
            if not T:
                continue
            want = "b" if T == "bytes" else "u"
            for a in ph.args:
                v = a.value
                if isinstance(v, pre_ir.UInt64Constant) and T == "bytes":
                    a.value = _itob_const(v.value)
                elif isinstance(v, pre_ir.BytesConstant) and T == "uint64":
                    a.value = _to_u64_const(v)
                elif (isinstance(v, pre_ir.Register) and id(v) not in phi_ids
                      and avm(v.ir_type) not in ("?", want)):
                    a.value = placeholder(T)   # cross-type non-phi seed -> dead placeholder


def _reconcile_mixed_phis(prog) -> None:
    """Re-type a phi-web left holding a wrong-AVM-type constant: a `bytes`
    accumulator slot is seeded with the cheaper `intc_0 0` (uint64 slots with
    empty `""`) before the loop fills it, so the loop-header phi merges the dead
    placeholder with the real value, which Puya's typed IR rejects. Per web (keyed
    by register *identity* -- `tmp%`/`cr%` names repeat across groups), one tier
    of hard evidence decides -- consumer > non-placeholder const > non-phi def --
    then retype and rewrite the dead placeholders to match; skip a web showing
    both types (a real merge)."""
    blocks = list(pre_ir.blocks(prog))
    parent: dict = {}                    # id(Register) -> id(Register)
    obj: dict = {}                       # id(Register) -> Register

    def find(x):
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def note(r):
        obj[id(r)] = r
        return id(r)

    phi_ids: set = set()
    for bb in blocks:
        for ph in bb.phis:
            phi_ids.add(note(ph.register))
            for a in ph.args:
                if isinstance(a.value, pre_ir.Register):
                    parent[find(note(ph.register))] = find(note(a.value))

    consumer, constev, defev = _collect_phi_evidence(blocks, find, phi_ids, parent)
    webtype = _decide_webtypes(phi_ids, find, consumer, constev, defev)
    _apply_webtypes(blocks, find, phi_ids, webtype)


def _unify_comparison_operands(prog) -> None:
    """The two operands of `==` / `!=` must share an AVM family — you cannot
    compare a uint64 to a byteslice (Algorand Python wouldn't emit it). When they
    disagree, retype the SOFT operand (a state read / load whose family was only
    guessed) to the family fixed by HARD evidence on the other side: a constant, a
    txn/global field, or a typed-op result. This corrects e.g. a global read that
    defaulted to uint64 but is compared against `txn Sender` (bytes) — the read's
    slot type was guessed wrong, and the comparison is the ground truth.

    Override only ever moves a SOFT operand; two hard operands that conflict are
    left for the encoder to flag (a genuine inconsistency). For well-typed
    contracts the operands already agree, so nothing changes."""
    producer: dict = {}                  # id(Register) -> defining Intrinsic
    for bb in pre_ir.blocks(prog):
        for o in bb.ops:
            if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
                for t in o.targets:
                    producer[id(t)] = o.source

    _REFINED = ("account", "asset", "application")  # biguint handled explicitly above

    def strength(v):
        """(strength, family) for a comparison operand — higher strength = more
        trustworthy evidence of the AVM family. HARD (4): a constant, a txn/global
        field, or a typed-op result. REFINED (3): a specific type (account/asset/
        application/biguint) — implies a typed source. BASE (2): plain bytes/uint64.
        BOOL (1): the cheapest default. UNKNOWN (0)."""
        if isinstance(v, pre_ir.UInt64Constant):
            return (4, "u")
        if isinstance(v, pre_ir.BytesConstant):
            return (4, "b")
        if not isinstance(v, pre_ir.Register):
            return (0, "?")
        src = producer.get(id(v))
        if src is not None:
            if src.op in _U64_OPS:
                return (4, "u")
            if src.op in _BYTES_OPS:
                return (4, "b")
            ft = _field_type(src.op, " ".join(str(i) for i in (src.immediates or [])))
            if ft == "uint64":
                return (4, "u")
            if ft == "bytes":
                return (4, "b")
        if v.ir_type == "biguint":       # Puya BigUInt is byteslice-backed; avm()
            return (3, "b")              # doesn't map it, so handle it explicitly
        t = avm(v.ir_type)               # 'b' / 'u' / '?'
        if t == "?":
            return (0, "?")
        s = 3 if v.ir_type in _REFINED else 1 if v.ir_type == "bool" else 2
        return (s, t)

    for bb in pre_ir.blocks(prog):
        for o in bb.ops:
            src = (o.source if isinstance(o, pre_ir.Assignment)
                   else o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else o)
            if not isinstance(src, pre_ir.Intrinsic) or src.op not in ("==", "!=") \
                    or len(src.args) != 2:
                continue
            a0, a1 = src.args
            (s0, f0), (s1, f1) = strength(a0), strength(a1)
            if f0 == "?" or f1 == "?" or f0 == f1:
                continue                 # agree (or unknown) -> nothing to do
            # cross-family conflict: retype the weaker operand to the stronger's
            # family (equal strength => genuine, leave for the encoder to flag).
            if s0 > s1 and isinstance(a1, pre_ir.Register):
                a1.ir_type = "uint64" if f0 == "u" else "bytes"
            elif s1 > s0 and isinstance(a0, pre_ir.Register):
                a0.ir_type = "uint64" if f1 == "u" else "bytes"


def _realign_call_returns(prog) -> None:
    """Re-pin each call-result register to its callee's (authoritative) return
    type. `_reconcile_mixed_phis` can retype a callee's return value to bytes
    without touching the caller's result registers, leaving the InvokeSubroutine
    assignment's targets the wrong type; align them (targets are positional,
    matching `returns`)."""
    sub_by_id = {s.id: s for s in prog.subroutines}
    for bb in pre_ir.blocks(prog):
        for o in bb.ops:
            if isinstance(o, pre_ir.Assignment) and isinstance(
                    o.source, pre_ir.InvokeSubroutine):
                callee = sub_by_id.get(o.source.target)
                if callee is None:
                    continue
                for i, t in enumerate(o.targets):
                    if i < len(callee.returns) and callee.returns[i] != "?":
                        t.ir_type = callee.returns[i]


def _propagate_copy_types(prog) -> None:
    """Propagate a reconciled AVM type across register-to-register copies to a
    fixpoint: a copy must preserve its operand's type, so when reconciliation
    retyped a source to bytes/uint64 its copy targets (frame locals, temps) must
    follow, else the copy fails Puya's assignment type check."""
    changed = True
    while changed:
        changed = False
        for bb in pre_ir.blocks(prog):
            for o in bb.ops:
                if not (isinstance(o, pre_ir.Assignment) and len(o.targets) == 1
                        and isinstance(o.source, pre_ir.Register)):
                    continue
                s, t = o.source, o.targets[0]
                if s.ir_type in ("bytes", "uint64") and t.ir_type != s.ir_type:
                    t.ir_type = s.ir_type            # forward: source -> target
                    changed = True
                elif t.ir_type in ("bytes", "uint64") and s.ir_type == "?":
                    s.ir_type = t.ir_type            # back: typed slot -> ? source
                    changed = True


def _untyped(subs):
    n = 0
    for sub in subs:
        for pp in sub.parameters:
            n += pp.register.ir_type == "?"
        n += sum(r == "?" for r in sub.returns)
        for bb in sub.body:
            for phi in bb.phis:
                n += phi.register.ir_type == "?"
            for op in bb.ops:
                if isinstance(op, pre_ir.Assignment):
                    n += sum(t.ir_type == "?" for t in op.targets)
    return n


def _infer_params_from_callers(lifter, pairs):
    # Sub args are passed via scratch / frame here, not callsub operands. The
    # caller's exit_stack top `nargs` (param order es[-nargs+i]) are the
    # args; type each by tracing its scratch store, and -- when it is a
    # `frame_dig` -- directly through to the caller subroutine's own param
    # (inter-procedural: the param index is the immediate + the caller's
    # nargs, independent of the fat-frame output shape).
    struct2ir = {sb: ir_s for ir_s, sb in pairs}

    def _arg_type(arg, owner_ir, owner_nargs):
        a = lifter.producer.get(arg) if isinstance(arg, SSAVar) else None
        if a is not None and a.op == "frame_dig" and owner_ir is not None:
            k = _imm0(a)
            if k is not None and -owner_nargs <= k <= -1:
                return owner_ir.parameters[owner_nargs + k].register.ir_type
        if isinstance(arg, (SSAVar, Phi)):
            rt = lifter.reg(arg).ir_type        # IR-level type is the complete one
            if rt != "?":                # (render + use / state / copy-load)
                return rt
        return lifter._ssa_type(arg)

    for ir_sub, s in pairs:
        nargs = len(ir_sub.parameters)
        if nargs == 0 or not s.callers:
            continue
        cols = [set() for _ in range(nargs)]
        for cs in s.callers:
            es = cs.callsub_bb.exit_stack
            if len(es) < nargs:
                continue
            owner = lifter.sub_of.get(cs.callsub_bb)
            owner_ir = struct2ir.get(owner)
            owner_nargs = lifter._sub_io(owner.entry_bb)[0] if owner else 0
            for i in range(nargs):
                ty = _arg_type(es[-nargs + i], owner_ir, owner_nargs)
                if ty and ty != "?":
                    cols[i].add(ty)
        for i, pp in enumerate(ir_sub.parameters):
            if pp.register.ir_type == "?" and len(cols[i]) == 1:
                pp.register.ir_type = next(iter(cols[i]))


def _arg_avm_type(v) -> str:
    """Lift type of a pre_ir call argument value (``?`` if not yet known)."""
    if isinstance(v, pre_ir.Register):
        return v.ir_type
    if isinstance(v, pre_ir.UInt64Constant):
        return "uint64"
    if isinstance(v, pre_ir.BytesConstant):
        return "bytes"
    return "?"


def _unify_params_from_call_args(subs) -> None:
    """Interprocedural param typing from the pre_ir ``InvokeSubroutine`` args.

    A still-``?`` parameter is filled with the AVM type its call sites agree on
    (``_avm_join`` -> None on a cross-family clash, so a genuine disagreement is
    left untouched). This is the direct, pre_ir-level counterpart to
    ``_infer_params_from_callers`` (which traces the SSA exit-stack / frame chain):
    it catches the case where args reach the call as already-typed pre_ir values
    but the frame/scratch trace doesn't ground out — e.g. params the lift left
    ``?`` that, without this, lower via the ``?`` -> uint64 default while their
    args are bytes (an ill-typed callee, rejected downstream). Monotonic
    (only ``?`` -> concrete), so it joins the recovery fixpoint."""
    sub_by_id = {s.id: s for s in subs}
    cols: dict = {}                       # sub_id -> list[set] per param position
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            # A call with results is an Assignment source; a VOID call is wrapped
            # in an IntrinsicOp (its `.intrinsic` holds the InvokeSubroutine).
            src = (o.source if isinstance(o, pre_ir.Assignment)
                   else o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
            if not isinstance(src, pre_ir.InvokeSubroutine):
                continue
            callee = sub_by_id.get(src.target)
            if callee is None or not callee.parameters:
                continue
            c = cols.setdefault(src.target, [set() for _ in callee.parameters])
            for i, a in enumerate(src.args):
                if i < len(c):
                    t = _arg_avm_type(a)
                    if t and t != "?":
                        c[i].add(t)
    for sid, cset in cols.items():
        for i, pp in enumerate(sub_by_id[sid].parameters):
            if pp.register.ir_type == "?" and i < len(cset):
                j = _avm_join(cset[i])
                if j is not None:
                    pp.register.ir_type = j


def _infer_args_from_params(subs) -> None:
    """Callee -> caller propagation: a still-``?`` call ARGUMENT register inherits
    the (known) type of the parameter it is passed to. The dual of
    ``_unify_params_from_call_args`` (caller -> callee). Without this, a value
    that is only ever forwarded into a typed param (e.g. an address threaded
    through to an `itxn_field Sender`, or a number into `Amount`) stays ``?`` and
    lowers via the ``?`` -> uint64 default — so a bytes param fed by it, or a u64
    param it feeds, ends up mismatched. Monotonic (only ``?`` -> concrete)."""
    sub_by_id = {s.id: s for s in subs}
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            src = (o.source if isinstance(o, pre_ir.Assignment)
                   else o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
            if not isinstance(src, pre_ir.InvokeSubroutine):
                continue
            callee = sub_by_id.get(src.target)
            if callee is None:
                continue
            for i, a in enumerate(src.args):
                if i >= len(callee.parameters):
                    break
                pt = callee.parameters[i].register.ir_type
                if pt and pt != "?" and isinstance(a, pre_ir.Register) \
                        and a.ir_type == "?":
                    a.ir_type = pt


def _infer_state_types(lifter):
    """Type state read *values* from the contract's own put schema: a value is
    whatever was put to its (constant) key. Reads each put value's *final*
    register type (top-first: value [0], key [1]); a key with conflicting put
    types stays unknown. The read value is output 1 for ``*_get_ex`` (did_exist
    at 0), the sole output for ``*_get``."""
    key_types: dict = {}
    for a in lifter.prog.assignments:
        if a.op in ("app_global_put", "app_local_put") and len(a.inputs) >= 2:
            key, v = _const_key(a.inputs[1]), a.inputs[0]
            if key is None:
                continue
            if isinstance(v, (SSAVar, Phi)):
                vt = lifter.reg(v).ir_type
                if vt == "?":                    # folded const lost its reg type
                    cv = getattr(v, "const_value", None)
                    if getattr(cv, "kind", None):
                        vt = "uint64" if cv.kind == "int" else "bytes"
            elif isinstance(v, Const):           # a constant put still types the key
                vt = "uint64" if v.kind == "int" else "bytes"
            else:
                vt = None
            if vt and vt != "?":
                key_types.setdefault(key, set()).add(vt)

    # Also seed from READ value types. A key never PUT with a determinate type in
    # THIS contract still needs unifying if it is read with CONFLICTING types
    # (e.g. an address read bytes by use vs a uint64-default sibling read); else a
    # state-forwarding optimiser pass substitutes one access's value into another's
    # wrong-typed register and rejects the cross-type assignment.
    for a in lifter.prog.assignments:
        if a.op in ("app_global_get", "app_local_get"):
            rv = a.outputs[0] if a.outputs else None
        elif a.op in ("app_global_get_ex", "app_local_get_ex"):
            rv = a.outputs[1] if len(a.outputs) > 1 else None
        else:
            continue
        if not isinstance(rv, (SSAVar, Phi)):
            continue
        rk = _const_key(a.inputs[0]) if a.inputs else None
        if rk is None:
            continue
        fam = avm(lifter.reg(rv).ir_type)
        if fam in ("b", "u"):
            key_types.setdefault(rk, set()).add("bytes" if fam == "b" else "uint64")

    def _resolve(types: set):
        # One put type -> that type. On a conflict, a `bytes` put is
        # authoritative: a Puya-typed key never mixes types, so a bytes/
        # uint64 clash means some reads of a bytes key (an address/hash) were
        # mistyped uint64 by an `==` peer and then re-stored -- resolve the
        # whole chain to bytes. (Puya-compiled contracts never conflict, so
        # this only fires on decompiled type-recovery slips.)
        if len(types) == 1:
            return next(iter(types))
        return "bytes" if "bytes" in types else None

    key_types = {k: t for k, s in key_types.items()
                 if (t := _resolve(s)) is not None}
    if not key_types:
        return
    for a in lifter.prog.assignments:
        if a.op in ("app_global_get", "app_local_get"):
            val = a.outputs[0] if a.outputs else None
            k = _const_key(a.inputs[0]) if a.inputs else None
        elif a.op in ("app_global_get_ex", "app_local_get_ex"):
            val = a.outputs[1] if len(a.outputs) > 1 else None
            k = _const_key(a.inputs[0]) if a.inputs else None
        elif a.op in ("app_global_put", "app_local_put") and len(a.inputs) >= 2:
            # The forwarding pass copies a put VALUE straight into a later read of
            # the key, so the put value must carry the key's decided type too.
            val = a.inputs[0]
            k = _const_key(a.inputs[1])
        else:
            continue
        if not isinstance(val, (SSAVar, Phi)):
            continue
        if k not in key_types:
            continue
        # The put is authoritative: a read of a key with one consistent put
        # type *is* that type. Correct a read mistyped by use-inference (e.g.
        # an address read typed uint64 by an `==` peer) -- else a value-cache
        # optimiser pass substitutes the stored value into the wrong-typed
        # register. For consistent (puya-compiled) contracts the read type
        # already matches, so this is a no-op there.
        r = lifter.reg(val)
        if r.ir_type != key_types[k]:
            r.ir_type = key_types[k]


def _propagate_copy_load_types(lifter):
    """Close the remaining untyped registers at the IR level, to a
    fixpoint: a copy / local store (``let l%N = <reg>``) takes its source
    register's type, and a scratch ``(load N)`` takes the type stored to
    its slot (via the reaching-def ``load_stores``). Iterated because a
    typed load feeds a copy that feeds another load. Runs last, after
    param / return / state inference have typed the leaves."""
    def _src_type(v):
        if isinstance(v, pre_ir.Register):
            return v.ir_type
        if isinstance(v, pre_ir.UInt64Constant):
            return "uint64"
        if isinstance(v, pre_ir.BytesConstant):
            return "bytes"
        return None                          # Intrinsic / invoke: not a copy

    # Monotonic: each step only turns a `?` into a concrete type, never the
    # reverse (every write is guarded by `== "?"`), so this can't oscillate
    # and converges in at worst one pass per register. Loop to the fixpoint
    # rather than capping the depth, so a long copy/load chain can't be left
    # half-typed.
    changed = True
    while changed:
        changed = False
        for bb in pre_ir.blocks(lifter.subs):
            for op in bb.ops:
                if (isinstance(op, pre_ir.Assignment) and len(op.targets) == 1
                        and op.targets[0].ir_type == "?"):
                    st = _src_type(op.source)
                    if st and st != "?":
                        op.targets[0].ir_type = st
                        changed = True
        for a in lifter.prog.assignments:
            if a.op != "load" or not a.outputs:
                continue
            out = a.outputs[0]
            if not isinstance(out, (SSAVar, Phi)) or lifter.reg(out).ir_type != "?":
                continue
            tys = {lifter.reg(s).ir_type for s in lifter.load_stores.get(out, ())
                   if isinstance(s, (SSAVar, Phi))} - {"?"}
            if len(tys) == 1:
                lifter.reg(out).ir_type = next(iter(tys))
                changed = True


def _unify_call_returns(lifter):
    # A callsite's result register and the callee's declared return are the
    # same value -- unify their AVM types both ways, and pin the callee's
    # SubroutineReturn value register too, so the callee types up internally.
    for cs_bb, regs in lifter.call_results.items():
        cs = lifter.callsite.get(cs_bb)
        callee = lifter.name2sub.get(cs.target_name) if cs else None
        if callee is None:
            continue
        for pos, rreg in enumerate(regs):
            if pos >= len(callee.returns):
                continue
            ret = callee.returns[pos]
            # The result register IS the callee's return value, so the two
            # types must be equal. The callee return (typed from the value
            # actually produced) is authoritative; on a cross-family clash
            # it overrides the caller's use-derived guess (e.g. a `bytes`
            # address result mis-typed `uint64` by an `==` peer). When the
            # callee is still `?`, the caller's concrete type informs it.
            if ret != "?":
                rreg.ir_type = ret
            elif rreg.ir_type != "?":
                callee.returns[pos] = ret = rreg.ir_type
                for b in callee.body:
                    t = b.terminator
                    if isinstance(t, pre_ir.SubroutineReturn) and pos < len(t.result):
                        rv = t.result[pos]
                        if isinstance(rv, pre_ir.Register) and rv.ir_type == "?":
                            rv.ir_type = ret


def _infer_select_types(subs) -> None:
    # `select C B A` pushes B or A chosen by the runtime condition C, so its
    # result shares ONE AVM type with both value operands. The args are
    # [C (condition, uint64), B, A]; type a `?` result from the value operands
    # (which agree by construction -- you cannot select between two different AVM
    # types). Skip arg 0 (the condition); a genuine type clash joins to None and
    # is left alone. Monotonic (only `?` -> concrete), so it joins the fixpoint.
    def _vt(v):
        if isinstance(v, pre_ir.Register):
            return v.ir_type
        if isinstance(v, pre_ir.UInt64Constant):
            return "uint64"
        if isinstance(v, pre_ir.BytesConstant):
            return "bytes"
        return "?"
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            if (isinstance(o, pre_ir.Assignment) and len(o.targets) == 1
                    and o.targets[0].ir_type == "?"):
                s = o.source
                if (isinstance(s, pre_ir.Intrinsic) and s.op == "select"
                        and len(s.args) == 3):
                    j = _avm_join(_vt(v) for v in s.args[1:])
                    if j is not None:
                        o.targets[0].ir_type = j


def _warn_residual_unknowns(subs) -> None:
    """Surface any register type recovery could NOT resolve. Lowering defaults a
    residual ``?`` to uint64 (``to_puya_ir._IRT``), which silently mistypes a
    value that is really bytes -- so make the gap visible instead of quiet. Not
    fatal (a genuinely-uint64 value defaults correctly), but logged so a recovery
    miss is caught rather than shipped as a wrong type."""
    res: list[str] = []
    for sub in subs:
        for pp in sub.parameters:
            if pp.register.ir_type == "?":
                res.append(f"{sub.id}:param {pp.register.name}")
        res += [f"{sub.id}:return[{i}]" for i, r in enumerate(sub.returns) if r == "?"]
        for bb in sub.body:
            res += [f"{sub.id}:phi {ph.register.name}" for ph in bb.phis
                    if ph.register.ir_type == "?"]
            for op in bb.ops:
                if isinstance(op, pre_ir.Assignment):
                    res += [f"{sub.id}:{t.name}" for t in op.targets if t.ir_type == "?"]
    if res:
        import logging
        logging.getLogger("tealql.tealtools.lift").warning(
            "type recovery left %d register(s) unresolved (lowering defaults them "
            "to uint64; a bytes value would be mistyped): %s%s",
            len(res), ", ".join(res[:12]), " …" if len(res) > 12 else "")


def recover_types(lifter, sub_pairs) -> None:
    """Run the type passes to a fixpoint -- they feed each other (a typed caller
    arg types a callee param; a typed value types the slots/loads of it; a put
    types its matching get; uses and phi args pin the rest). Each is monotonic
    (only ``?`` -> concrete), so the untyped count falls and this terminates."""
    subs = lifter.subs
    prev = -1
    while prev != _untyped(subs):
        prev = _untyped(subs)
        _infer_types_from_uses(subs)
        # Propagate typed params back to ?-args BEFORE the SSA-frame trace, so a
        # value forwarded only into a typed param (e.g. into itxn_field Sender /
        # Amount) is typed by that param rather than mis-guessed by the trace
        # (which fills ?-params, so it then skips the now-typed one).
        _infer_args_from_params(subs)
        _infer_params_from_callers(lifter, sub_pairs)
        _unify_params_from_call_args(subs)
        _unify_phi_types(subs)
        _infer_select_types(subs)
        _infer_state_types(lifter)
        _propagate_copy_load_types(lifter)
        _infer_returns(subs)
        _unify_call_returns(lifter)
    _warn_residual_unknowns(subs)


def _reconcile_return_arity(prog) -> None:
    """A subroutine returns a FIXED number of values, but an early / fail return
    path can leave the deepest return value off its (re-simulated) exit stack, so
    the lift builds a SHORT ``SubroutineReturn`` there; ``_infer_returns`` then
    zip-truncates the signature, yielding a callee whose declared arity is less
    than the values its call sites consume (Puya: ``source = (uint64), target =
    (uint64, uint64)``). Reconcile to the widest return site: widen the signature,
    and front-pad each short site with a typed-zero for the missing (deepest)
    positions so every site and the signature agree on arity. The padded slot is
    a fail/early path the caller's result is not expected to read (the real value
    was never computed there); the behavioural test is the gate on that."""
    for sub in prog.subroutines:
        sites = [b.terminator for b in sub.body
                 if isinstance(b.terminator, pre_ir.SubroutineReturn)]
        if not sites:
            continue
        n = max([len(sub.returns)] + [len(t.result) for t in sites])
        if n == 0:
            continue
        # Re-derive EVERY position from the authoritative widest (arity-complete,
        # deepest-first) site, not just the appended tail: _infer_returns may have
        # zip-truncated sub.returns down to a SHORT site whose positions are
        # logically SHALLOWER than the widest site's, so trusting the existing
        # prefix (append-only widening) leaves position 0 mis-typed (e.g. a bytes
        # deepest return recorded as uint64). Keep an existing value only where the
        # widest slot is still `?` (don't clobber a good caller-derived type).
        widest = max(sites, key=lambda t: len(t.result)).result
        old = list(sub.returns)
        types = []
        for i in range(n):
            wt = getattr(widest[i], "ir_type", "?") if i < len(widest) else "?"
            if wt not in ("?", None):
                types.append(wt)
            elif i < len(old) and old[i] != "?":
                types.append(old[i])
            else:
                types.append("uint64")        # lowering default
        sub.returns = types
        for t in sites:                        # front-pad short return sites
            if len(t.result) < n:
                pad = [pre_ir.BytesConstant("0x") if types[i] == "bytes"
                       else pre_ir.UInt64Constant(0)
                       for i in range(n - len(t.result))]
                t.result = pad + list(t.result)


def _fix_branch_conditions(prog) -> None:
    """A ``ConditionalBranch`` condition MUST be uint64-backed -- Puya rejects a
    bytes one outright (``Branch condition can only be uint64 backed value``), a
    HARD error, unlike the arg-type mismatches on intrinsics which it only *logs*.
    A branch condition is uint64 at runtime by construction (``bnz``/``bz`` pop a
    uint64), so a bytes-typed one is a recovery mislabel. Relabel it uint64 --
    which is the SAFE direction: a uint64 value reaching a bytes op is tolerated,
    only the reverse is fatal, so the condition's other uses stay valid. Its
    *definition* must agree, and does whenever the producer is a uint64 op
    (`+`/`-`/cmp), a schema-flexible read (state / txn field), or a copy/phi of
    one -- which is every branch condition in practice (you cannot branch on a
    genuine byte-string). Reactive: only the fatal sites are touched, so a
    contract that already lifts is left exactly as-is."""
    for b in pre_ir.blocks(prog):
        t = b.terminator
        if isinstance(t, pre_ir.ConditionalBranch) and isinstance(t.condition, pre_ir.Register):
            if t.condition.ir_type in _BYTES_FAMILY:
                t.condition.ir_type = "uint64"


def finalize_types(prog) -> None:
    """Reconcile and re-align types on the assembled pre_ir.Program (post-fixpoint):
    re-type placeholder-seeded mixed phi webs, widen varying-arity subroutine
    returns to one fixed count, propagate the result across call-result registers
    and copies, then force branch conditions uint64 (Puya hard-rejects bytes ones)."""
    _reconcile_mixed_phis(prog)
    _reconcile_return_arity(prog)
    _realign_call_returns(prog)
    _propagate_copy_types(prog)
    _unify_comparison_operands(prog)
    _fix_branch_conditions(prog)
