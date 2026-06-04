"""AVM type / phi recovery for the lift (see :mod:`lift`).

After :class:`lift._Lifter` builds the IR, some registers are still ``?`` (params
/ returns crossing subroutines, scratch loads, state reads, placeholder phi webs).
:func:`recover_types` closes them with a monotonic per-sub fixpoint;
:func:`finalize_types` reconciles mixed-type phi webs on the assembled program.
Both read the lifter's maps via a duck-typed ``lifter`` (never imports lift).
"""
from __future__ import annotations


from . import pre_ir
from ..ssa import Const, Phi, SSAVar
from .optypes import _BYTES_CONSUME, _U64_CONSUME, _imm0, avm
from .teal_const import _const_bytes


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
    except Exception:
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
    "getbit": ("uint64", "bytes"),
    "setbyte": ("uint64", "uint64", "bytes"),     # A(bytes) B(idx) C(val)
    "extract3": ("uint64", "uint64", "bytes"),    # A(bytes) B(start) C(len)
    "substring3": ("uint64", "uint64", "bytes"),
    "extract_uint16": ("uint64", "bytes"),        # A(bytes) B(offset)
    "extract_uint32": ("uint64", "bytes"),
    "extract_uint64": ("uint64", "bytes"),
    "replace3": ("bytes", "uint64", "bytes"),     # A(bytes) B(start) C(bytes)
    "extract": ("bytes",),                        # extract s l A(bytes)
    "app_global_get": ("bytes",),                 # key
    "app_global_put": (None, "bytes"),            # K(key) V(val) -> [V, K]
    "bzero": ("uint64",), "txnas": ("uint64",), "gtxnas": ("uint64",),
}


def _expected_type(op, idx, args):
    """Expected ``ir_type`` of ``args[idx]`` for ``op``, or ``None``."""
    if op == "__cond__":
        return "uint64"
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

    def use(r, op, idx, args):
        if isinstance(r, pre_ir.Register):
            reg_by_id[id(r)] = r
            uses.setdefault(id(r), []).append((op, idx, args))

    def note(vp):
        if isinstance(vp, (pre_ir.Intrinsic, pre_ir.InvokeSubroutine)):
            op = vp.op if isinstance(vp, pre_ir.Intrinsic) else None
            for i, a in enumerate(vp.args):
                use(a, op, i, vp.args)

    for sub in subs:
        for b in sub.body:
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

    # Monotonic (only `?` -> a concrete type, guarded by `!= "?"`), so loop to
    # the fixpoint: guaranteed to terminate, with no depth cap to truncate a
    # long use-chain.
    changed = True
    while changed:
        changed = False
        for rid, r in reg_by_id.items():
            if r.ir_type != "?":
                continue
            inferred = {et for (op, i, args) in uses.get(rid, [])
                        if (et := _expected_type(op, i, args)) and et != "?"}
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
        for sub in subs:
            for b in sub.body:
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


def _reconcile_mixed_phis(prog) -> None:
    """Re-type a phi-web left holding a wrong-AVM-type constant: a `bytes`
    accumulator slot is seeded with the cheaper `intc_0 0` (uint64 slots with
    empty `""`) before the loop fills it, so the loop-header phi merges the dead
    placeholder with the real value, which Puya's typed IR rejects. Per web (keyed
    by register *identity* -- `tmp%`/`cr%` names repeat across groups), one tier
    of hard evidence decides -- consumer > non-placeholder const > non-phi def --
    then retype and rewrite the dead placeholders to match; skip a web showing
    both types (a real merge)."""
    blocks = [bb for sub in [prog.main, *prog.subroutines] for bb in sub.body]
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

    def reg_args(x):
        out = []
        if isinstance(x, pre_ir.Register):
            out.append(x)
        for a in (getattr(x, "args", None) or []) + (getattr(x, "values", None) or []):
            out += reg_args(a)
        return out

    # Evidence in priority tiers, aggregated per web root. A phi-web's type is
    # decided by, in order: how its values are *consumed* (strongest -- the seed
    # of a wrong type is dead and can't be consumed as that type anyway), then a
    # non-placeholder constant arg, then a non-phi member's own def type.
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
                    for r in reg_args(src):
                        if id(r) in phi_ids:
                            consumer[find(id(r))].add(k)
            if isinstance(o, pre_ir.Assert):
                for r in reg_args(o.condition):
                    if id(r) in phi_ids:
                        consumer[find(id(r))].add("u")

    webtype: dict = {}                   # web root -> 'bytes' / 'uint64'
    for root in {find(rid) for rid in phi_ids}:
        for tier in (consumer, constev, defev):
            ev = tier.get(root, set())
            if len(ev) == 1:             # unanimous at this tier decides it
                webtype[root] = "bytes" if "b" in ev else "uint64"
                break

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


def _realign_call_returns(prog) -> None:
    """Re-pin each call-result register to its callee's (authoritative) return
    type. `_reconcile_mixed_phis` can retype a callee's return value to bytes
    without touching the caller's result registers, leaving the InvokeSubroutine
    assignment's targets the wrong type; align them (targets are positional,
    matching `returns`)."""
    sub_by_id = {s.id: s for s in prog.subroutines}
    for sub in [prog.main, *prog.subroutines]:
        for bb in sub.body:
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
        for sub in [prog.main, *prog.subroutines]:
            for bb in sub.body:
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
        elif a.op in ("app_global_get_ex", "app_local_get_ex"):
            val = a.outputs[1] if len(a.outputs) > 1 else None
        else:
            continue
        if not isinstance(val, (SSAVar, Phi)):
            continue
        k = _const_key(a.inputs[0]) if a.inputs else None
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
        for sub in lifter.subs:
            for bb in sub.body:
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
        _infer_params_from_callers(lifter, sub_pairs)
        _unify_phi_types(subs)
        _infer_state_types(lifter)
        _propagate_copy_load_types(lifter)
        _infer_returns(subs)
        _unify_call_returns(lifter)


def finalize_types(prog) -> None:
    """Reconcile and re-align types on the assembled pre_ir.Program (post-fixpoint):
    re-type placeholder-seeded mixed phi webs, then propagate the result across
    call-result registers and copies."""
    _reconcile_mixed_phis(prog)
    _realign_call_returns(prog)
    _propagate_copy_types(prog)
