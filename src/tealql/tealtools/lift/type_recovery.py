"""AVM type / phi recovery for the lift (see :mod:`lift`).

:func:`recover_types` closes the registers :class:`lift._Lifter` leaves ``?``
(params / returns crossing subroutines, scratch loads, state reads, placeholder
phi webs) with a monotonic fixpoint; :func:`finalize_types` reconciles mixed-type
phi webs on the assembled program. Both reach the lifter's maps duck-typed,
never importing lift.

HAZARD: recovery must stay a PURE ANNOTATION -- it may only refine a register
WITHIN one AVM family (same avm_type, coarse -> fine). Crossing the uint64/bytes
divide changes what the program lowers to, i.e. its semantics.
"""
from __future__ import annotations

import logging

from ..ssa import Const, Phi, SSAVar
from ..ssa.operands import imm0 as _imm0
from . import pre_ir
from ..language.avm import (_BYTES_CONSUME, _BYTES_OPS, _U64_CONSUME, _U64_OPS,
                      _field_type, avm, txn_field_avm_type)
from .teal_const import _const_bytes

logger = logging.getLogger("tealql.tealtools.lift")


def _empty_bytes(b) -> bool:
    """True if a BytesConstant is the empty-bytes placeholder (`""` / `0x`)."""
    v = (getattr(b, "value", "") or "").strip()
    return v in ("", "0x", '""', "''")


def _itxn_field_avm(field: str):
    """The AVM type (``'b'``/``'u'``) an ``itxn_field <Field>`` operand must be,
    from the canonical langspec table in ``avm.py``; None for an unknown field."""
    return txn_field_avm_type(field)


def _itob_const(v: int) -> "pre_ir.BytesConstant":
    """A uint64 placeholder as bytes: empty for the dead 0 seed, else its itob form."""
    return pre_ir.BytesConstant("0x" if v == 0 else "0x" + v.to_bytes(8, "big").hex())


def _to_u64_const(b) -> "pre_ir.UInt64Constant":
    """A bytes placeholder as uint64: empty -> 0, else its btoi value."""
    try:
        raw, _ = _const_bytes(getattr(b, "value", "") or "0x")
        return pre_ir.UInt64Constant(int.from_bytes(raw[-8:], "big") if raw else 0)
    except Exception:
        return pre_ir.UInt64Constant(0)


def _const_key(operand) -> "str | None":
    """The constant bytes value of a state-key operand (verbatim ``0x…`` hex), or
    ``None`` for a dynamic key, which cannot be matched across put / get."""
    if isinstance(operand, Const):
        return operand.value if operand.kind == "bytes" else None
    cv = getattr(operand, "const_value", None)
    if cv is not None and getattr(cv, "kind", None) == "bytes":
        return cv.value
    return None


# HAZARD: must agree with avm.py's `avm()` and `_AVM_BYTES_TYPES` on what is
# bytes-backed. A type bytes-backed in one table but not the other makes a phi
# join of two genuinely-bytes types cross the divide and default to uint64.
# `string` is bytes-backed (an ARC-4 String is a length-prefixed byte array),
# and so is `biguint` (a big-endian number IN a byte slice).
_BYTES_FAMILY = frozenset({"bytes", "account", "string", "biguint"})


_U64_FAMILY = frozenset({"uint64", "bool", "asset", "application"})


def _avm_join(types) -> str | None:
    """Common AVM type of a set of lift type strings, or None if they cross the
    uint64/bytes divide — Puya checks the *AVM* type, so `account` and `bytes`
    unify to `bytes`, `bool` and `uint64` to `uint64`."""
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
    # INDEX-operand ops: every stack input is a uint64 index (group index,
    # scratch slot, array index). Their absence was not a missing refinement but
    # a missing SIGNAL: a value consumed only by `gtxns` got no expected-type at
    # all, stayed `?`, and lowered to bytes -- so `gtxns Receiver` was handed a
    # byteslice where the AVM wants a uint64 group index. That is exactly the
    # shape of an ARC-4 transaction parameter (`transfer(pay,axfer,...)`), which
    # is passed to a subroutine AS its group index, so every such sub took
    # bytes-typed params and mismatched its own call sites.
    "gtxns", "gtxnsa", "gtxnsas", "gloads", "gloadss", "gaids", "args",
    "itxnas", "loads",
})


_BYTES_IN_ALL = frozenset({
    "concat", "len", "btoi", "sha256", "sha512_256", "keccak256", "sha3_256",
    "bsqrt", "b+", "b-", "b*", "b/", "b%", "b|", "b&", "b^", "b~",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
    # `log` takes a byteslice; an ARC-4 event payload that reaches it only
    # through a frame slot otherwise has no typing signal at all.
    "log",
})


# Position-specific input types, indexed by SSA arg position.
# HAZARD: positions are **top-first** — args[0] is the topmost popped value, so a
# TEAL op documented ``op A B C`` (A deepest, C on top) has SSA args [C, B, A].
# ``None`` = leave the value unknown.
_POS_IN = {
    "getbyte": ("uint64", "bytes"),               # A(bytes) B(idx) -> [B, A]
    # getbit is POLYMORPHIC (value operand A is uint64 OR a byteslice); forcing
    # `bytes` mis-types a uint64 BITMAP and clashes with the u64 store of the same
    # scratch slot. Leave A unknown so the VALUE FLOW types it; index B is uint64.
    "getbit": ("uint64", None),
    # `setbit A B C` is polymorphic in its VALUE operand (A) — see
    # _infer_setbit_types, which unifies it with the result — but the bit index
    # and bit value are always uint64.
    "setbit": ("uint64", "uint64", None),         # A(poly) B(idx) C(bit)
    # `select A B C` picks A or B on condition C. The VALUES are polymorphic
    # (joined by _infer_select_types); only the condition is fixed.
    "select": ("uint64", None, None),             # A(poly) B(poly) C(cond)
    # `app_opted_in A B`: the application id is uint64, but the ACCOUNT operand
    # is polymorphic in the AVM — an address byteslice OR a uint64 index into
    # the Accounts array — so it is deliberately left to the value flow.
    "app_opted_in": ("uint64", None),             # A(poly acct) B(app id)
    # The immediate-keyed (field-selecting) ops. Their operand types are the
    # SAME across every field variant — only the RESULT varies with the field —
    # so one entry each. These were the last untyped positions: an asset id
    # reaching `asset_params_get` and nothing else had no typing signal at all.
    "app_params_get":    ("uint64",),             # A(app id)
    "asset_params_get":  ("uint64",),             # A(asset id)
    "asset_holding_get": ("uint64", None),        # A(poly acct) B(asset id)
    "block":             ("uint64",),             # A(round)
    "gitxnas":           ("uint64",),             # A(array index)
    "json_ref":          ("bytes", "bytes"),      # A(json object) B(key)
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
    # local-state ops mirror the global ones plus the DEEPEST account operand;
    # without these the key stays `?` and lowers to uint64, giving an
    # app_local_get(uint64, uint64) mixed-type encode error.
    "app_local_get": ("bytes", None),            # acct key -> [key, acct]
    "app_local_put": (None, "bytes", None),      # acct key val -> [val, key, acct]
    "app_local_get_ex": ("bytes", "uint64", None),  # acct app key -> [key, app, acct]
    # the `del` siblings carry a bytes key too — same lowering error.
    "app_global_del": ("bytes",),                # key
    "app_local_del": ("bytes", None),            # acct key -> [key, acct]
    "bzero": ("uint64",), "txnas": ("uint64",), "gtxnas": ("uint64",),
    # `stores A B` -- A(slot) B(value); top-first SSA is [value, slot]. Only the
    # slot is typed: the stored value is deliberately polymorphic.
    "stores": (None, "uint64"),
    # box ops: the NAME is the deepest operand (so last, top-first) and always
    # bytes; without this a name reaching box_get only through a frame slot stays
    # `?` and lowers to uint64. Position-precise, so the u64 start/len/size
    # operands stay uint64.
    "box_get": ("bytes",), "box_len": ("bytes",), "box_del": ("bytes",),
    "box_create": ("uint64", "bytes"),            # name size -> [size, name]
    "box_resize": ("uint64", "bytes"),
    "box_put": ("bytes", "bytes"),                # name value -> [value, name]
    "box_extract": ("uint64", "uint64", "bytes"), # name start len
    "box_replace": ("bytes", "uint64", "bytes"),  # name start value
    "box_splice": ("bytes", "uint64", "uint64", "bytes"),  # name start len value
    # The one signature-verify op with a non-bytes operand: the recovery id is a
    # uint64, so it cannot ride the all-bytes family set with its siblings.
    "ecdsa_pk_recover": ("bytes", "bytes", "uint64", "bytes"),  # data id sigA sigB
}


def _expected_type(op, idx, args, imm=None):
    """Expected ``ir_type`` of ``args[idx]`` for ``op``, or ``None``."""
    if op in ("__cond__", "__exit__"):
        return "uint64"
    if op == "itxn_field" and idx == 0 and imm:
        # The operand of `itxn_field <Field>` must be the field's AVM type;
        # without this a non-phi value feeding an address field stays `?` and
        # lowers to uint64, which Puya's backend rejects.
        a = _itxn_field_avm(str(imm[0]).strip())
        return "bytes" if a == "b" else "uint64" if a == "u" else None
    if op in _U64_IN_ALL:
        return "uint64"
    if op in _BYTES_IN_ALL:
        return "bytes"
    pos = _POS_IN.get(op)
    if pos is not None:
        # AUTHORITATIVE for the ops it lists, including the positions it
        # deliberately leaves `None` (getbit's polymorphic value operand, the
        # state ops' schema-dependent value). Returning here stops the
        # family fallback below from overriding a considered "unknown".
        return pos[idx] if idx < len(pos) else None
    if op in ("==", "!=") and len(args) == 2:
        other = args[1 - idx]
        ot = getattr(other, "ir_type", None)
        return ot if ot and ot != "?" else None
    # Ops the tables above do not list still type their operands unambiguously —
    # fall back to the AVM-wide sets, which are the same source the phi-web
    # reconciliation already consults. Keeping a second, narrower copy of that
    # knowledge here is what let the whole signature-verify family go untyped:
    # a pubkey read by app_global_get_ex and used ONLY by ed25519verify_bare had
    # no typed use at all, stayed `?`, and to-puya defaulted it to uint64 -> a
    # Bytes/uint64 lowering error that made the contract uncompilable.
    if op in _BYTES_CONSUME:
        return "bytes"
    if op in _U64_CONSUME:
        return "uint64"
    return None


def _infer_types_from_uses(subs) -> None:
    """Refine ``?``-typed registers from the ops that consume them: arithmetic and
    branch inputs uint64, bytes-op inputs bytes, ``==`` matching its peer."""
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
            # `return` pops a uint64 success value, pinning its producer. Often
            # the only typing signal when the returned value comes from an
            # unconstrained source (`gloads` on another group txn's scratch).
            use(t.result, "__exit__", 0, [t.result])

    # Monotonic (only `?` -> concrete), so the fixpoint terminates; no depth cap,
    # so a long use-chain is never truncated.
    changed = True
    while changed:
        changed = False
        for rid, r in reg_by_id.items():
            if r.ir_type != "?":
                continue
            inferred = {et for (op, i, args, imm) in uses.get(rid, [])
                        if (et := _expected_type(op, i, args, imm)) and et != "?"}
            # Unify WITHIN an AVM family: uses that all agree on bytes-vs-uint64
            # pin the register even when their refined strings differ (e.g. a
            # value both `len`'d -> "bytes" and `==`'d against an address peer ->
            # "account" is unambiguously bytes; the raw-set unanimity guard used
            # to see two strings and bail to `?`, which then defaulted to uint64
            # -> a Bytes/uint64 mixed-type lowering error). A genuine uint64/bytes
            # clash joins to None and is left `?`. Monotonic (only `?` -> concrete).
            j = _avm_join(inferred)
            if j is not None:
                r.ir_type = j
                changed = True


def _infer_returns(subs) -> None:
    """Set each subroutine's return types from the first typed ``SubroutineReturn``
    value per position, across return sites."""
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
            # monotonic: keep positions already typed (e.g. pinned from a
            # caller), fill only the `?` ones.
            old = sub.returns
            sub.returns = [o if o != "?" else n
                           for o, n in zip(old, rets)] if len(old) == len(rets) \
                else rets


def _unify_phi_types(subs) -> None:
    # A phi merges one logical value, so its register and every arg share an AVM
    # type; propagate BOTH ways. Monotonic (only `?` -> concrete), so the fixpoint
    # terminates and no phi web is left half-typed.
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
                        # REGISTERS ONLY. Every other operand class is a frozen
                        # dataclass, so assigning to one raises
                        # `FrozenInstanceError` and takes the whole lift down —
                        # and `Undefined`, whose `ir_type` IS `"?"`, is exactly
                        # such an operand. It reaches a phi argument wherever a
                        # merge has an arm with no value (a predecessor that
                        # arrives too shallow), so the crash is reachable from
                        # ordinary control flow, not just from experiments.
                        # Skipping is also the RIGHT answer, not merely a safe
                        # one: a constant already carries its own type, and an
                        # unknown has none to fix.
                        if (isinstance(a.value, pre_ir.Register)
                                and a.value.ir_type == "?"):
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
    """Per-web type evidence in priority tiers -- `(consumer, constev, defev)`,
    each `web-root -> {"u"|"b"}`. Consumption is strongest: a wrongly-typed seed
    is dead and cannot be consumed as that type anyway."""
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
            # Consumer evidence counts only *phi* registers: a seed register's own
            # uses elsewhere say nothing about the accumulator it merely seeds.
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
                # POSITIONAL expectations too, not just whole-op families. An
                # op can pin one operand without being uniformly typed, and
                # those were invisible here: `extract3`'s START is uint64 while
                # its array operand is bytes, so a loop index whose web was
                # seeded by a bytes placeholder stayed bytes all the way into
                # the slice and puya rejected the intrinsic. Same tier as the
                # evidence above — a consumer is a consumer.
                for i, a in enumerate(src.args):
                    if not isinstance(a, pre_ir.Register) or id(a) not in phi_ids:
                        continue
                    et = _hard_expected_type(src.op, i, src.args, src.immediates)
                    f = avm(et) if et else None
                    if f in ("u", "b"):
                        consumer[find(id(a))].add(f)
            if isinstance(o, pre_ir.Assert):
                for r in _reg_args(o.condition):
                    if id(r) in phi_ids:
                        consumer[find(id(r))].add("u")
    return consumer, constev, defev


def _decide_webtypes(phi_ids, find, consumer, constev, defev) -> dict:
    """Pick each web's type from the first tier with a unanimous vote; a web with
    no real evidence at any tier is a dead placeholder -> collapse to uint64."""
    webtype: dict = {}                   # web root -> 'bytes' / 'uint64'
    for root in {find(rid) for rid in phi_ids}:
        for tier in (consumer, constev, defev):
            ev = tier.get(root, set())
            if len(ev) == 1:             # unanimous at this tier decides it
                webtype[root] = "bytes" if "b" in ev else "uint64"
                break
        else:
            # No evidence at ANY tier -> a DEAD-placeholder web: every const arg
            # is a zero / empty coarse-SSA seed and nothing consumes it as a type.
            # Such a web merges differently-typed dead seeds and Puya rejects the
            # cross-type phi, but the value is never used, so collapse it to the
            # uint64 lowering default. A web with any REAL evidence is left for
            # the encoder to flag as a true conflict.
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
    """Re-type a phi-web left holding a wrong-AVM-type constant -- a `bytes`
    accumulator seeded with the cheaper `intc_0 0` merges the dead placeholder
    with the real value at the loop header, which Puya's typed IR rejects.

    Per web (keyed by register IDENTITY -- `tmp%`/`cr%` names repeat across
    groups), one tier of hard evidence decides (consumer > non-placeholder const
    > non-phi def), then the placeholders are rewritten to match. A web showing
    both types is a real merge and is skipped."""
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
    """The two operands of `==` / `!=` must share an AVM family, so retype the
    SOFT operand (a state read whose family was only guessed) to the family fixed
    by HARD evidence on the other side — a constant, a txn/global field, or a
    typed-op result.

    HAZARD: an override may only ever move a SOFT operand. Two HARD operands that
    conflict are left for the encoder to flag; letting a guess overwrite a
    well-typed operand would mint a family the value does not have."""
    producer: dict = {}                  # id(Register) -> defining Intrinsic
    for bb in pre_ir.blocks(prog):
        for o in bb.ops:
            if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
                for t in o.targets:
                    producer[id(t)] = o.source

    _REFINED = ("account", "asset", "application")

    def strength(v):
        """(strength, family) for a comparison operand. HARD (4) = a constant,
        txn/global field, or typed-op result — fixed by the AVM itself, and the
        only strength trusted to drive a retype. REFINED (3) =
        account/asset/application; BASE (2) = plain bytes/uint64; BOOL (1) = the
        cheapest default; UNKNOWN (0)."""
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
            # Cross-family conflict (impossible at runtime, so one side is a
            # recovery error): retype the OTHER operand, but ONLY when the trusted
            # side is HARD — see the docstring.
            if s0 == 4 and s1 < 4 and isinstance(a1, pre_ir.Register):
                a1.ir_type = "uint64" if f0 == "u" else "bytes"
            elif s1 == 4 and s0 < 4 and isinstance(a0, pre_ir.Register):
                a0.ir_type = "uint64" if f1 == "u" else "bytes"


def _realign_call_returns(prog) -> None:
    """Re-pin each call-result register to its callee's authoritative return type
    — `_reconcile_mixed_phis` can retype a callee return without touching the
    caller's result registers (targets are positional, matching `returns`)."""
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
    fixpoint — a copy must preserve its operand's type or it fails Puya's
    assignment type check."""
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
    # The args are the callsub's OWN operands, TOP-FIRST, so param `i` (0 =
    # deepest) is `inputs[nargs - 1 - i]`. They used to be read off the caller's
    # `exit_stack` top, which held them only while a callsub was modelled as
    # consuming nothing; that slot is now the call's RESULT, so every parameter
    # would have been typed from the wrong value.
    # Type each arg by tracing it, and when it is a `frame_dig` go straight
    # through to the caller's own param — index = immediate + caller nargs.
    struct2ir = {sb: ir_s for ir_s, sb in pairs}

    def _arg_type(arg, owner_ir, owner_nargs):
        a = lifter.producer.get(arg) if isinstance(arg, SSAVar) else None
        if a is not None and a.op == "frame_dig" and owner_ir is not None:
            k = _imm0(a)
            if k is not None and -owner_nargs <= k <= -1:
                return owner_ir.parameters[owner_nargs + k].register.ir_type
        if isinstance(arg, (SSAVar, Phi)):
            rt = lifter.reg(arg).ir_type        # IR-level type is the complete one
            if rt != "?":
                return rt
        return lifter._ssa_type(arg)

    for ir_sub, s in pairs:
        nargs = len(ir_sub.parameters)
        if nargs == 0 or not s.callers:
            continue
        cols = [set() for _ in range(nargs)]
        for cs in s.callers:
            bb = cs.callsub_bb
            call = next((x for x in reversed(getattr(bb, "assignments", ()))
                         if x.op == "callsub"), None)
            if call is None or len(call.inputs) != nargs:
                continue        # an unresolved operand shifts every index: skip
            owner = lifter.sub_of.get(bb)
            owner_ir = struct2ir.get(owner)
            owner_nargs = lifter._sub_io(owner.entry_bb)[0] if owner else 0
            for i in range(nargs):
                ty = _arg_type(call.inputs[nargs - 1 - i], owner_ir, owner_nargs)
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
    """Fill a still-``?`` parameter with the AVM type its pre_ir
    ``InvokeSubroutine`` call sites agree on (``_avm_join`` -> None on a
    cross-family clash, so a genuine disagreement is left untouched).

    The pre_ir-level counterpart to ``_infer_params_from_callers``, which traces
    the SSA exit-stack / frame chain: this catches args that reach the call
    already typed but whose frame/scratch trace does not ground out. Monotonic,
    so it joins the recovery fixpoint."""
    sub_by_id = {s.id: s for s in subs}
    cols: dict = {}                       # sub_id -> list[set] per param position
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            # A call with results is an Assignment source; a VOID call is wrapped
            # in an IntrinsicOp (`.intrinsic` holds the InvokeSubroutine).
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
    the type of the parameter it is passed to. The dual of
    ``_unify_params_from_call_args``; without it a value only ever forwarded into
    a typed param stays ``?`` and lowers via the ``?`` -> uint64 default."""
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
    """Type state read VALUES from the contract's own put schema -- a value is
    whatever was put to its constant key; a key with conflicting put types stays
    unknown. Put inputs are top-first (value [0], key [1]); the read value is
    output 1 for ``*_get_ex`` (did_exist at 0), the sole output for ``*_get``."""
    key_types: dict = {}
    for a in lifter.prog.stack_assignments:
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

    # Also seed from READ value types: a key never PUT with a determinate type
    # here still needs unifying if it is read with CONFLICTING types, else a
    # state-forwarding pass substitutes one access's value into another's
    # wrong-typed register and rejects the cross-type assignment.
    for a in lifter.prog.stack_assignments:
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
        # ONE put type -> that type. HAZARD: a genuine bytes/uint64 clash is left
        # UNRESOLVED. Forcing the chain to bytes crosses the avm_type divide by
        # fiat and propagates into lowering — a real semantic change made on a
        # guess about which side was mistyped. Recovery only refines WITHIN a
        # family, so it stays a pure annotation.
        if len(types) == 1:
            return next(iter(types))
        return None

    key_types = {k: t for k, s in key_types.items()
                 if (t := _resolve(s)) is not None}
    if not key_types:
        return
    for a in lifter.prog.stack_assignments:
        if a.op in ("app_global_get", "app_local_get"):
            val = a.outputs[0] if a.outputs else None
            k = _const_key(a.inputs[0]) if a.inputs else None
        elif a.op in ("app_global_get_ex", "app_local_get_ex"):
            val = a.outputs[1] if len(a.outputs) > 1 else None
            k = _const_key(a.inputs[0]) if a.inputs else None
        elif a.op in ("app_global_put", "app_local_put") and len(a.inputs) >= 2:
            # The forwarding pass copies a put VALUE into a later read of the key,
            # so the put value must carry the key's decided type too.
            val = a.inputs[0]
            k = _const_key(a.inputs[1])
        else:
            continue
        if not isinstance(val, (SSAVar, Phi)):
            continue
        if k not in key_types:
            continue
        # The put is authoritative: a read of a key with one consistent put type
        # IS that type. Corrects a read mistyped by use-inference, else a
        # value-cache pass substitutes the stored value into the wrong-typed
        # register.
        r = lifter.reg(val)
        if r.ir_type != key_types[k]:
            r.ir_type = key_types[k]


def _propagate_copy_load_types(lifter):
    """Close the remaining untyped registers to a fixpoint: a copy takes its
    source register's type, a scratch ``(load N)`` the type stored to its slot
    (via the reaching-def ``load_stores``). Runs last, after param / return /
    state inference have typed the leaves."""
    def _src_type(v):
        if isinstance(v, pre_ir.Register):
            return v.ir_type
        if isinstance(v, pre_ir.UInt64Constant):
            return "uint64"
        if isinstance(v, pre_ir.BytesConstant):
            return "bytes"
        return None                          # Intrinsic / invoke: not a copy

    # Monotonic (every write is guarded by `== "?"`), so this cannot oscillate;
    # loop to the fixpoint so a long copy/load chain is never left half-typed.
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
        for a in lifter.prog.stack_assignments:
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
    # A callsite's result register and the callee's declared return are the same
    # value: unify both ways, and pin the callee's SubroutineReturn register too
    # so the callee types up internally.
    for cs_bb, regs in lifter.call_results.items():
        cs = lifter.callsite.get(cs_bb)
        callee = lifter.name2sub.get(cs.target_name) if cs else None
        if callee is None:
            continue
        for pos, rreg in enumerate(regs):
            if pos >= len(callee.returns):
                continue
            ret = callee.returns[pos]
            # The callee return, typed from the value actually produced, is
            # authoritative and overrides the caller's use-derived guess on a
            # cross-family clash; when the callee is still `?`, the caller's
            # concrete type informs it.
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
    # `select C B A` returns B or A, so the result shares ONE AVM type with both
    # value operands. Args are top-first [C, B, A] — skip arg 0 (the uint64
    # condition) and join the value operands; a genuine clash joins to None.
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


def _infer_setbit_types(subs) -> None:
    # `setbit A B C` is POLYMORPHIC (uint64 OR byteslice) but TYPE-PRESERVING: the
    # result has A's AVM type. SSA args are top-first [C (bit), B (index),
    # A (value)], so A is args[2]. Unify a `?` result with A and vice versa, so an
    # ARC-4 bool-pack chain seeded by `0x00` stays `bytes` instead of each
    # intermediate defaulting to uint64.
    def _vt(v):
        if isinstance(v, pre_ir.Register):       return v.ir_type
        if isinstance(v, pre_ir.UInt64Constant): return "uint64"
        if isinstance(v, pre_ir.BytesConstant):  return "bytes"
        return "?"
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            if not (isinstance(o, pre_ir.Assignment) and len(o.targets) == 1):
                continue
            s = o.source
            if not (isinstance(s, pre_ir.Intrinsic) and s.op == "setbit"
                    and len(s.args) == 3):
                continue
            val, res = s.args[2], o.targets[0]
            rt, vt = res.ir_type, _vt(val)
            if rt == "?" and vt != "?":
                res.ir_type = vt                              # value type -> ? result
            elif isinstance(val, pre_ir.Register) and val.ir_type == "?" and rt != "?":
                val.ir_type = rt                              # result type -> ? value


def _warn_residual_unknowns(subs) -> None:
    """Log any register type recovery could NOT resolve.

    HAZARD: lowering defaults a residual ``?`` to uint64 (``to_puya_ir._IRT``),
    silently mistyping a value that is really bytes. Not fatal, but the gap must
    be visible rather than shipped as a wrong type."""
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
    arg types a callee param, a typed value types the slots/loads of it, a put
    types its matching get). Each is monotonic, so the untyped count falls and
    this terminates."""
    subs = lifter.subs
    prev = -1
    while prev != _untyped(subs):
        prev = _untyped(subs)
        _infer_types_from_uses(subs)
        # Propagate typed params back to ?-args BEFORE the SSA-frame trace: a
        # value forwarded only into a typed param should be typed by that param
        # rather than mis-guessed by the trace.
        _infer_args_from_params(subs)
        _infer_params_from_callers(lifter, sub_pairs)
        _unify_params_from_call_args(subs)
        _unify_phi_types(subs)
        _infer_select_types(subs)
        _infer_setbit_types(subs)
        _infer_state_types(lifter)
        _propagate_copy_load_types(lifter)
        _infer_returns(subs)
        _unify_call_returns(lifter)
    _warn_residual_unknowns(subs)


def _reconcile_return_arity(prog) -> None:
    """Widen every ``SubroutineReturn`` site and the signature to one fixed arity.

    An early / fail return path can leave the deepest value off its simulated
    exit stack, so the lift builds a SHORT site and ``_infer_returns``
    zip-truncates the signature below what call sites consume. Short sites are
    FRONT-padded with a typed zero for the missing (deepest) positions; those
    slots are fail paths whose result the caller is not expected to read."""
    for sub in prog.subroutines:
        sites = [b.terminator for b in sub.body
                 if isinstance(b.terminator, pre_ir.SubroutineReturn)]
        if not sites:
            continue
        n = max([len(sub.returns)] + [len(t.result) for t in sites])
        if n == 0:
            continue
        # Re-derive EVERY position from the widest (arity-complete, deepest-first)
        # site, not just the appended tail: _infer_returns may have truncated
        # sub.returns to a SHORT site whose positions are logically SHALLOWER, so
        # trusting the existing prefix leaves position 0 mis-typed. Keep an
        # existing value only where the widest slot is still `?`.
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
                # By FAMILY, not by the name `bytes`: these types come from a
                # register's recovered ir_type, so they can be any refined
                # bytes-backed name (`account`, `biguint`, `string`), and
                # padding one of those with a uint64 crosses the AVM divide.
                pad = [pre_ir.BytesConstant("0x") if types[i] in _BYTES_FAMILY
                       else pre_ir.UInt64Constant(0)
                       for i in range(n - len(t.result))]
                t.result = pad + list(t.result)


def _fix_branch_conditions(prog) -> None:
    """Relabel a bytes-typed ``ConditionalBranch`` condition uint64 — Puya HARD-
    rejects a bytes one, unlike the intrinsic arg-type mismatches it merely logs.

    A branch condition is uint64 at runtime by construction (``bnz``/``bz`` pop a
    uint64), so a bytes label is a recovery mislabel, and uint64 is the SAFE
    direction: a uint64 reaching a bytes op is tolerated, only the reverse is
    fatal. Reactive — only the fatal sites are touched."""
    for b in pre_ir.blocks(prog):
        t = b.terminator
        if isinstance(t, pre_ir.ConditionalBranch) and isinstance(t.condition, pre_ir.Register):
            if t.condition.ir_type in _BYTES_FAMILY:
                t.condition.ir_type = "uint64"


def _avm_fixed_family(src):
    """``'u'`` / ``'b'`` when an ``Intrinsic``'s RESULT type is fixed by the AVM
    (a typed opcode or a typed txn/global field), else ``None``. The producer-side
    twin of :func:`_hard_expected_type`, and the same HARD tier
    :func:`_unify_comparison_operands`'s strength ladder trusts."""
    if not isinstance(src, pre_ir.Intrinsic):
        return None
    if src.op in _U64_OPS:
        return "u"
    if src.op in _BYTES_OPS:
        return "b"
    # Through avm(): a field's type is often the REFINED name (`txn Sender` is
    # "account", not "bytes"), which is every bit as AVM-fixed.
    ft = _field_type(src.op, " ".join(str(i) for i in (src.immediates or [])))
    f = avm(ft) if ft else "?"
    return f if f in ("u", "b") else None


def _hard_expected_type(op, idx, args, imm):
    """``_expected_type`` restricted to LANGSPEC-FORCED positions.

    Excludes ``==``/``!=``, whose expectation is merely its peer's current label
    — relative evidence, already arbitrated by ``_unify_comparison_operands``'s
    strength ladder. What is left is fixed by the AVM itself: the ``_POS_IN``
    table, an ``itxn_field``'s field type, the all-uint64 / all-bytes op sets,
    and a branch/exit condition."""
    if op in ("==", "!="):
        return None
    return _expected_type(op, idx, args, imm)


def _coerce_constant_operands(prog) -> None:
    """A CONSTANT in a langspec-forced uint64 position must BE a uint64.

    :func:`_fix_langspec_operand_types` consults exactly this evidence but skips
    anything that is not a ``Register``, so a constant in a contradicting
    position was never corrected. The empty bytes constant is how it shows up:
    an unresolved value lowers to the typed-zero placeholder, and where the
    register's reconstructed type was bytes that placeholder is ``0x`` — which
    then feeds ``itob`` / ``-`` / ``>`` and puya reports ``received =
    (bytes[0]), expected = (AVMType.uint64)``.

    The operand POSITION is the authority here, exactly as in
    :func:`to_puya_ir._coerce_slice_operands`, which does this for
    ``extract3``/``substring3`` alone — this generalises it to every position
    the langspec pins, and does it on the pre-IR so the lowered IR is right by
    construction rather than repaired afterwards.

    ONE DIRECTION ONLY. A bytes constant in a uint64 slot has a defined reading
    (empty -> 0, else its ``btoi``); a uint64 constant in a BYTES slot does not,
    because the expected width is the field's, not the value's — ``itob``-ing an
    int into an ``itxn_field Receiver`` would invent an 8-byte address. Those
    stay for :func:`_warn_residual_unknowns` to surface."""
    for b in pre_ir.blocks(prog):
        for o in b.ops:
            vp = (o.source if isinstance(o, pre_ir.Assignment)
                  else o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
            if not isinstance(vp, pre_ir.Intrinsic):
                continue
            for i, a in enumerate(vp.args):
                if not isinstance(a, pre_ir.BytesConstant):
                    continue
                et = _hard_expected_type(vp.op, i, vp.args, vp.immediates)
                if et and avm(et) == "u":
                    vp.args[i] = _to_u64_const(a)


def _stamp_undefined_operands(prog) -> None:
    """Give a direct unknown operand the AVM family its opcode requires.

    ``Undefined`` deliberately carries no inferred value, but Puya still needs
    a concrete representation type. Its generic ``?`` fallback is uint64,
    which makes an honest refused frame read fail lowering when consumed by a
    bytes-only op such as ``extract``. Stamping the langspec-required family
    chooses no value and loses no information; it only makes the explicit
    unknown well-typed at its use site.
    """
    for block in pre_ir.blocks(prog):
        for op in block.ops:
            provider = (op.source if isinstance(op, pre_ir.Assignment)
                        else op.intrinsic
                        if isinstance(op, pre_ir.IntrinsicOp) else None)
            if not isinstance(provider, pre_ir.Intrinsic):
                continue
            for index, value in enumerate(provider.args):
                if not isinstance(value, pre_ir.Undefined):
                    continue
                expected = _hard_expected_type(
                    provider.op, index, provider.args, provider.immediates)
                if expected is not None and value.ir_type != expected:
                    provider.args[index] = pre_ir.Undefined(ir_type=expected)


def _fix_langspec_operand_types(prog) -> None:
    """Correct a register whose recovered type CONTRADICTS the AVM's own.

    Reactive, like :func:`_fix_branch_conditions`, but for the mismatches Puya
    merely LOGS instead of rejecting. It is needed because the recovery fixpoint
    is monotone ``?`` -> concrete (:func:`_infer_types_from_uses` skips any
    register already labelled), so nothing downstream can undo a wrong label —
    and two passes above hand out wrong labels by design: an unresolved return
    position becomes ``"uint64"`` in :func:`_reconcile_return_arity` (the
    lowering default) and :func:`_realign_call_returns` then re-pins the
    caller's result register to it. A recipient address arriving that way stayed
    uint64 into ``itxn_field Receiver``, which cost it the ``arc4.Address``
    recovery that ``box_recovery`` / ``abi_address_fund_flows`` read, and emitted
    an intrinsic puya reports as type-invalid.

    Correct only where the hard uses AGREE. A register pulled both ways is a
    real ambiguity, and ``_warn_residual_unknowns`` surfacing it beats a coin
    flip. Where the value is a call result, the callee's declared return moves
    with it — but ONLY if every caller agrees; a genuine disagreement is left
    standing so ``specialize_polymorphic_returns`` can clone the callee per type,
    which is precisely the evidence ``_realign_call_returns`` used to erase.

    A value whose PRODUCER is AVM-fixed is never touched: ``txn Sender`` returns
    bytes whatever consumes it, so a use-side disagreement there means the error
    is elsewhere, and relabelling the producer's result just moves puya's
    complaint from the argument to the return."""
    want: dict = {}                        # id(reg) -> {"uint64"/"bytes"} | None
    reg_by_id: dict = {}

    def note(vp):
        if not isinstance(vp, pre_ir.Intrinsic):
            return
        for i, a in enumerate(vp.args):
            if not isinstance(a, pre_ir.Register):
                continue
            et = _hard_expected_type(vp.op, i, vp.args, vp.immediates)
            f = avm(et) if et else "?"
            if f in ("u", "b"):
                reg_by_id[id(a)] = a
                want.setdefault(id(a), set()).add(et)

    fixed: set = set()                     # registers the AVM already types
    for b in pre_ir.blocks(prog):
        for o in b.ops:
            note(o.source if isinstance(o, pre_ir.Assignment)
                 else o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
            if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
                if _avm_fixed_family(o.source) is not None:
                    fixed.update(id(t) for t in o.targets)

    # Call results: which (callee, position) a register came out of, and every
    # register that shares that slot — a retype is only safe if they all agree.
    sub_by_id = {s.id: s for s in prog.subroutines}
    slot_of: dict = {}                     # id(reg) -> (callee, pos)
    slot_regs: dict = {}                   # (callee_id, pos) -> [reg, ...]
    for b in pre_ir.blocks(prog):
        for o in b.ops:
            if isinstance(o, pre_ir.Assignment) and isinstance(
                    o.source, pre_ir.InvokeSubroutine):
                callee = sub_by_id.get(o.source.target)
                if callee is None:
                    continue
                for pos, t in enumerate(o.targets):
                    if isinstance(t, pre_ir.Register):
                        slot_of[id(t)] = (callee, pos)
                        slot_regs.setdefault((callee.id, pos), []).append(t)

    phi_targets = {id(ph.register) for b in pre_ir.blocks(prog) for ph in b.phis
                   if isinstance(ph.register, pre_ir.Register)}

    for rid, types in want.items():
        if len({avm(t) for t in types}) != 1:
            continue                       # hard uses disagree -> genuine ambiguity
        r = reg_by_id[rid]
        et = next(iter(types))
        if avm(r.ir_type) == avm(et):
            continue                       # already the right family
        # An UNSET register is resolved here too, not just a contradicting one.
        # The fixpoint owns `?` in general, but it cannot reach every producer:
        # `app_global_get_ex` returns (any, bool), and the `any` half stayed `?`
        # all the way to lowering, whose default is uint64 — so a recipient
        # address read out of global state arrived at `itxn_field Receiver` as a
        # uint64 and puya reported the intrinsic type-invalid. Agreeing hard uses
        # are better evidence than a default, and every guard below still
        # applies, so a phi web, an AVM-fixed producer or a disputed call slot is
        # still left alone.
        if rid in phi_targets:
            continue                       # a phi web is _reconcile_mixed_phis' job
        if rid in fixed:
            continue                       # producer is AVM-fixed -> it wins
        slot = slot_of.get(rid)
        sites = []
        if slot is not None:
            callee, pos = slot
            for cb in callee.body:
                t = cb.terminator
                if isinstance(t, pre_ir.SubroutineReturn) and pos < len(t.result):
                    rv = t.result[pos]
                    if isinstance(rv, pre_ir.Register):
                        sites.append(rv)
            # The value the callee actually returns may itself be AVM-fixed (a
            # sub whose tail is `txn Sender`). Then the use expectation is the
            # side that is wrong, and retyping either end only relocates puya's
            # complaint from the argument to the return.
            if any(id(rv) in fixed and avm(rv.ir_type) != avm(et) for rv in sites):
                continue
        r.ir_type = et
        if slot is None:
            continue
        callee, pos = slot
        peers = slot_regs.get((callee.id, pos), ())
        if any(avm(p.ir_type) != avm(et) for p in peers):
            continue                       # callers disagree -> let specialize clone
        if pos < len(callee.returns):
            callee.returns[pos] = et
        for rv in sites:                   # keep the return sites consistent
            if id(rv) not in fixed and avm(rv.ir_type) != avm(et):
                rv.ir_type = et


def finalize_types(prog) -> None:
    """Reconcile types on the assembled ``pre_ir.Program`` after the fixpoint:
    mixed phi webs, varying-arity returns, call-result and copy propagation,
    correcting anything that contradicts the AVM, then forcing branch conditions
    uint64."""
    _reconcile_mixed_phis(prog)
    _reconcile_return_arity(prog)
    _realign_call_returns(prog)
    # After the two passes above have handed out lowering defaults, and BEFORE
    # copy propagation spreads them.
    _fix_langspec_operand_types(prog)
    _stamp_undefined_operands(prog)
    _coerce_constant_operands(prog)
    _propagate_copy_types(prog)
    _unify_comparison_operands(prog)
    _fix_branch_conditions(prog)
