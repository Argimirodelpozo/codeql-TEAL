"""Lower an :class:`~tealtools.ssa.SSAProgram` into the Puya-shaped IR model.

``lower(prog) -> ir.Program``. Transforms our SSA into the Puya IR classes in
:mod:`tealtools.experimental_3.ir`, which self-render in the ``.ssa.slot.ir``
shape.

Two structural rewrites happen here (both contained — no substrate change):

- **Subroutine partitioning** via :func:`tealtools.structure.analyze_structure`:
  routing + handler BBs become ``main``; each ``callsub``-reachable routine
  becomes an ``ir.Subroutine`` with params from its ``proto``. ``callsub`` ->
  ``ir.InvokeSubroutine`` + continue; ``retsub`` -> ``ir.SubroutineReturn``.

- **Frame modeling** (de-noises the unroll): PySSA's ``_try_expand_frame_op``
  models ``frame_dig``/``frame_bury`` as ~1000-wide stack ops over the
  ``[1..STACK_MAX]`` unroll, so the deep stack-slot phis exist only to feed
  them. Here ``frame_dig -k`` (k within proto args) reads parameter ``nargs-k``
  and ``frame_dig``/``frame_bury`` on other slots read/write a local — single
  values, severing the stack dependency. The fat frame ops are dropped, and the
  now-unreferenced stack-model phis are pruned by forward liveness. Heuristic
  (best-effort on locals / odd frame shapes), but it removes essentially all of
  the unroll noise.

Constants and trivial single-predecessor phis are inlined; type/field tables
are shared with :mod:`tealtools.experimental_3.puya_ir`.
"""
from __future__ import annotations

from . import ir
from ..block_args import to_block_args
from ..ssa import (
    Const, Phi, SSAProgram, SSAVar, _STACK_SHUFFLE_OPS, _TERMINATOR_OPS,
    _shuffle_mapping,
)
from ..structure import analyze_structure
from .puya_ir import (
    _BOOL_OPS, _BYTES_OPS, _COND_BRANCH, _NAME_PREFIX, _U64_OPS, _field_type,
)

_FRAME_OPS = frozenset({"frame_dig", "frame_bury"})


def _const(cv: Const):
    if cv.kind == "uint64":
        try:
            return ir.UInt64Constant(int(cv.value))
        except ValueError:
            return ir.UInt64Constant(0)
    return ir.BytesConstant(cv.value)


def _imm0(a) -> int | None:
    toks = (a.immediates or "").split()
    if not toks:
        return None
    try:
        return int(toks[0])
    except ValueError:
        return None


def lower(prog: SSAProgram) -> ir.Program:
    form = to_block_args(prog)
    label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in prog.labels}

    struct = analyze_structure(prog)
    sub_of = {bb: s for s in struct.subroutines for bb in s.body}
    callsite = {cs.callsub_bb: cs for cs in struct.call_sites}

    # SSA-level producer map + scratch reaching-def (per `load N`, the value
    # SSAVars its influencing `store N`s wrote) -- used to type call args,
    # which are passed via scratch (load/store) here, not as callsub operands.
    producer = {o: a for a in prog.assignments
                for o in a.outputs if isinstance(o, SSAVar)}
    load_stores: dict = {}
    g = getattr(prog, "_graph", None)
    if g is not None:
        for n in g.nodes:
            stores = g.nodes[n].get("scratch_stores")
            if not stores:
                continue
            lv = prog.var(n.location.file, n.location.start_line, 1)
            if lv is not None:
                load_stores[lv] = [prog.var(*k) for k in stores]

    def _key(bb):
        return (bb.file, bb.first_line)

    all_blocks = sorted(prog.blocks.values(), key=_key)
    main_blocks = [bb for bb in all_blocks if bb not in sub_of]
    groups = [("main", None, main_blocks)]
    for s in sorted(struct.subroutines, key=lambda s: _key(s.entry_bb)):
        groups.append((s.name or f"sub@L{s.entry_bb.first_line}", s,
                       sorted(s.body, key=_key)))

    bid = {bb: i for i, bb in enumerate(all_blocks)}
    line2block = {bb.first_line: bb for bb in all_blocks}

    def type_of(o, op=None, imm=None) -> str:
        if op in _BOOL_OPS:
            return "bool"
        ft = _field_type(op, imm)
        if ft:
            return ft
        t = getattr(o, "type", None)
        if t is not None and getattr(t, "kind", None):
            return t.kind
        if getattr(o, "range", None) is not None:
            return "uint64"
        if op in _U64_OPS:
            return "uint64"
        if op in _BYTES_OPS:
            return "bytes"
        return "?"

    regs: dict = {}
    ctr: dict = {}
    frame_map: dict = {}              # SSAVar (frame_dig out[0]) -> Register
    local_regs: dict = {}            # (gname, slot) -> Register
    shuffle_src: dict = {}           # SSAVar (shuffle output) -> source operand
    cur_gname = "main"

    def _new_reg(prefix: str, ir_type: str) -> ir.Register:
        n = ctr.get(prefix, 0)
        ctr[prefix] = n + 1
        return ir.Register(f"{prefix}%{n}", 0, ir_type)

    def _local(slot: int) -> ir.Register:
        key = (cur_gname, slot)
        if key not in local_regs:
            local_regs[key] = ir.Register(f"l%{slot}", 0, "?")
        return local_regs[key]

    def _is_real_phi(ph: Phi) -> bool:
        bb = ph.basic_block
        return bb is not None and len(bb.predecessors) > 1

    def reg(o) -> ir.Register:
        if o in frame_map:
            return frame_map[o]
        if o not in regs:
            regs[o] = _new_reg("v", type_of(o))
        return regs[o]

    def _setup_frame(gb, params):
        nargs = len(params)
        for bb in gb:
            for a in bb.assignments:
                if a.op == "frame_dig" and a.outputs:
                    k = _imm0(a)
                    if k is None:
                        continue
                    out0 = a.outputs[0]
                    if -nargs <= k <= -1:
                        frame_map[out0] = params[nargs + k].register
                    else:
                        frame_map[out0] = _local(k)

    def _setup_shuffles(gb):
        # A pure stack shuffle (dup/dupn/swap/…) just routes values; map each
        # output to its source so consumers reference the value directly and
        # the op drops out (Puya is value-based, no shuffles). Restricted to
        # shuffles of *constants* -- routing value-carrying shuffles would
        # re-expose fat-frame stack vars and undo the param/frame mapping; the
        # real leftovers (dup/dupn of 0 / 0x) are all const anyway.
        for bb in gb:
            for a in bb.assignments:
                if a.op not in _STACK_SHUFFLE_OPS:
                    continue
                m = _shuffle_mapping(a)
                if m is None:
                    continue
                for i, src_idx in enumerate(m):
                    if i < len(a.outputs) and 0 <= src_idx < len(a.inputs):
                        out = a.outputs[i]
                        src = a.inputs[src_idx]
                        is_const = (isinstance(src, Const)
                                    or getattr(src, "const_value", None) is not None)
                        if isinstance(out, SSAVar) and is_const:
                            shuffle_src[out] = src

    def _is_routed_shuffle(a) -> bool:
        if a.op not in _STACK_SHUFFLE_OPS:
            return False
        outs = [o for o in a.outputs if isinstance(o, SSAVar)]
        return bool(outs) and all(o in shuffle_src for o in outs)

    def _name_group(gb):
        ctr.clear()
        for bb in gb:
            if len(bb.predecessors) > 1:
                for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                    if ph not in regs:
                        regs[ph] = _new_reg("tmp", type_of(ph))
            for a in bb.assignments:
                if a.op in _FRAME_OPS:
                    continue                       # frame outputs map to params/locals
                if _is_routed_shuffle(a):
                    continue                       # const shuffle outputs route to sources
                if a.op in _TERMINATOR_OPS and a.op != "callsub":
                    continue
                if a.op in ("intcblock", "bytecblock", "proto"):
                    continue
                if (len(a.outputs) == 1 and not a.inputs
                        and getattr(a.outputs[0], "const_value", None) is not None):
                    continue
                pfx = "tmp" if a.op == "callsub" else _NAME_PREFIX.get(a.op, "tmp")
                for o in a.outputs:
                    if isinstance(o, SSAVar) and o not in regs:
                        regs[o] = _new_reg(pfx, type_of(o, a.op, a.immediates))

    def value(o, _seen=None):
        seen = _seen if _seen is not None else set()
        while True:
            if isinstance(o, SSAVar) and o in shuffle_src and id(o) not in seen:
                seen.add(id(o))
                o = shuffle_src[o]               # route through stack shuffles
                continue
            if isinstance(o, Phi) and not _is_real_phi(o) and id(o) not in seen:
                b = o.basic_block
                if b is not None and len(b.predecessors) == 1:
                    seen.add(id(o))
                    es = b.predecessors[0].exit_stack
                    k = o.stack_index
                    nxt = es[-k] if 0 < k <= len(es) else None
                    if nxt is not None:
                        o = nxt                  # inline trivial single-pred phi
                        continue
            break
        cv = getattr(o, "const_value", None)
        if cv is not None:
            return _const(cv)
        if o is None:
            return ir.Undefined()
        if isinstance(o, Const):
            return _const(o)
        return reg(o)

    def term_assign(bb):
        last = None
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS:
                last = a
        return last

    def control(bb):
        t = term_assign(bb)
        op = t.op if t is not None else None
        if op == "callsub":
            cs = callsite.get(bb)
            cont = cs.continuation_bb if cs else None
            if cont is not None and cont in bid:
                return ir.Goto(bid[cont])
            return ir.SubroutineReturn([])
        succ = [s for s in bb.successors if s in bid]
        if not succ:
            if op == "return":
                v = (value(bb.exit_stack[-1]) if bb.exit_stack
                     else ir.UInt64Constant(0))
                return ir.ProgramExit(v)
            if op == "err":
                return ir.Fail()
            if op == "retsub":
                return ir.SubroutineReturn([value(i) for i in (t.inputs or [])])
            return ir.ProgramExit(ir.UInt64Constant(0))
        if len(succ) == 1:
            return ir.Goto(bid[succ[0]])
        if len(succ) == 2 and op in _COND_BRANCH and t is not None:
            cond = value(t.inputs[0]) if t.inputs else ir.Undefined()
            taken = line2block.get(label2line.get((t.immediates or "").strip()))
            if taken in succ:
                other = succ[0] if succ[1] is taken else succ[1]
            else:
                taken, other = succ[0], succ[1]
            if op == "bnz":
                return ir.ConditionalBranch(cond, bid[taken], bid[other])
            return ir.ConditionalBranch(cond, bid[other], bid[taken])  # bz
        if op in ("switch", "match"):
            return ir.GotoNth(value(t.inputs[0]) if (t and t.inputs) else ir.Undefined(),
                              [bid[s] for s in succ[:-1]], bid[succ[-1]])
        return ir.GotoNth(ir.Undefined(), [bid[s] for s in succ[:-1]], bid[succ[-1]])

    def _build_block(bb):
        phis = []
        if len(bb.predecessors) > 1:
            params = list(form.params.get(bb, []))
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                i = params.index(ph) if ph in params else None
                args = []
                for pred in bb.predecessors:
                    if pred not in bid:
                        continue
                    e = form.edge(pred, bb)
                    val = (e.args[i] if (e is not None and i is not None
                                         and i < len(e.args)) else None)
                    args.append(ir.PhiArgument(value(val), bid[pred]))
                phis.append(ir.Phi(reg(ph), args))
        ops = []
        for a in bb.assignments:
            if _is_routed_shuffle(a):
                continue                            # const shuffle routed to source
            if a.op == "frame_dig":
                continue                            # a param/local read (no op)
            if a.op == "frame_bury":
                slot = _imm0(a)
                if slot is not None and a.inputs:
                    ops.append(ir.Assignment([_local(slot)], value(a.inputs[0])))
                continue
            if a.op == "callsub":
                cs = callsite.get(bb)
                target = (cs.target_name if cs and cs.target_name
                          else (a.immediates or "?"))
                # Args are passed via scratch, not callsub operands, so take the
                # caller's exit_stack top nargs in param order (es[-nargs+i]).
                nargs = _proto_io(cs.target_entry)[0] if (cs and cs.target_entry) else 0
                es = bb.exit_stack
                if nargs and len(es) >= nargs:
                    call_args = [value(es[-nargs + i]) for i in range(nargs)]
                else:
                    call_args = [value(i) for i in a.inputs]
                invoke = ir.InvokeSubroutine(target, call_args)
                shown = [o for o in a.outputs if isinstance(o, SSAVar)]
                ops.append(ir.Assignment([reg(o) for o in shown], invoke)
                           if shown else ir.IntrinsicOp(invoke))
                continue
            if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock",
                                                   "proto"):
                continue
            if (len(a.outputs) == 1 and not a.inputs
                    and getattr(a.outputs[0], "const_value", None) is not None):
                continue
            args = [value(i) for i in a.inputs]
            intr = ir.Intrinsic(a.op, a.immediates.split() if a.immediates else [],
                                args)
            shown = [o for o in a.outputs if isinstance(o, SSAVar)]
            if a.op == "assert" and not shown:
                ops.append(ir.Assert(args[0] if args else ir.Undefined()))
            elif shown:
                ops.append(ir.Assignment([reg(o) for o in shown], intr))
            else:
                ops.append(ir.IntrinsicOp(intr))
        return ir.BasicBlock(id=bid[bb], phis=phis, ops=ops,
                             terminator=control(bb), comment=f"L{bb.first_line}")

    def _ssa_type(o, depth=0):
        """Type an SSA operand by its producing op, tracing scratch loads
        through the reaching-def to the stored value's type, and frame reads
        through to the param/local register they map to."""
        if isinstance(o, Const):
            return o.kind
        if not isinstance(o, SSAVar) or depth > 6:
            return "?"
        if o in frame_map:                       # a param/local read
            return frame_map[o].ir_type
        a = producer.get(o)
        op = a.op if a else None
        imm = a.immediates if a else None
        if op in _BOOL_OPS:
            return "bool"
        ft = _field_type(op, imm)
        if ft:
            return ft
        t = getattr(o, "type", None)
        if t is not None and getattr(t, "kind", None):
            return t.kind
        if getattr(o, "range", None) is not None:
            return "uint64"
        if op in _U64_OPS:
            return "uint64"
        if op in _BYTES_OPS:
            return "bytes"
        if o in load_stores:
            ts = {_ssa_type(s, depth + 1) for s in load_stores[o] if s is not None}
            ts.discard("?")
            if len(ts) == 1:
                return next(iter(ts))
        return "?"

    def _infer_params_from_callers(pairs):
        # Sub args are passed via scratch / frame here, not callsub operands. The
        # caller's exit_stack top `nargs` (param order es[-nargs+i]) are the
        # args; type each by tracing its scratch store, and -- when it is a
        # `frame_dig` -- directly through to the caller subroutine's own param
        # (inter-procedural: the param index is the immediate + the caller's
        # nargs, independent of the fat-frame output shape).
        struct2ir = {sb: ir_s for ir_s, sb in pairs}

        def _arg_type(arg, owner_ir, owner_nargs):
            a = producer.get(arg) if isinstance(arg, SSAVar) else None
            if a is not None and a.op == "frame_dig" and owner_ir is not None:
                k = _imm0(a)
                if k is not None and -owner_nargs <= k <= -1:
                    return owner_ir.parameters[owner_nargs + k].register.ir_type
            return _ssa_type(arg)

        for ir_sub, s in pairs:
            nargs = len(ir_sub.parameters)
            if nargs == 0 or not s.callers:
                continue
            cols = [set() for _ in range(nargs)]
            for cs in s.callers:
                es = cs.callsub_bb.exit_stack
                if len(es) < nargs:
                    continue
                owner = sub_of.get(cs.callsub_bb)
                owner_ir = struct2ir.get(owner)
                owner_nargs = _proto_io(owner.entry_bb)[0] if owner else 0
                for i in range(nargs):
                    ty = _arg_type(es[-nargs + i], owner_ir, owner_nargs)
                    if ty and ty != "?":
                        cols[i].add(ty)
            for i, pp in enumerate(ir_sub.parameters):
                if pp.register.ir_type == "?" and len(cols[i]) == 1:
                    pp.register.ir_type = next(iter(cols[i]))

    subs = []
    sub_pairs = []                                # (ir.Subroutine, struct.Subroutine)
    for gname, s, gb in groups:
        cur_gname = gname
        if s is None:
            params, nrets = [], 0
        else:
            nargs, nrets = _proto_io(s.entry_bb)
            params = [ir.Parameter(ir.Register(f"p%{i}", 0, "?"))
                      for i in range(nargs)]
        _setup_frame(gb, params)
        _setup_shuffles(gb)
        _name_group(gb)
        body = [_build_block(bb) for bb in gb]
        if s is None:
            file = all_blocks[0].file.split("/")[-1] if all_blocks else "program"
            subs.append(ir.Subroutine(id=file, parameters=[], returns=[],
                                      body=body, is_main=True))
        else:
            sub_ir = ir.Subroutine(id=gname, parameters=params,
                                   returns=["?"] * nrets, body=body)
            subs.append(sub_ir)
            sub_pairs.append((sub_ir, s))

    _prune_dead_phis(subs)
    _infer_types_from_uses(subs)

    def _typed_params():
        return sum(pp.register.ir_type != "?"
                   for ir_sub, _ in sub_pairs for pp in ir_sub.parameters)

    for _ in range(8):                   # fixpoint: a sub typed this round can
        before = _typed_params()         # type another's frame-passed arg next
        _infer_params_from_callers(sub_pairs)
        if _typed_params() == before:
            break
    _unify_phi_types(subs)
    _infer_returns(subs)

    main = next(sub for sub in subs if sub.is_main)
    return ir.Program(main=main, subroutines=[s for s in subs if not s.is_main])


def _proto_io(entry_bb):
    for a in entry_bb.assignments:
        if a.op == "proto":
            toks = (a.immediates or "").split()
            if len(toks) >= 2:
                try:
                    return int(toks[0]), int(toks[1])
                except ValueError:
                    break
    return 0, 0


def _collect_regs(x, into: set) -> None:
    if isinstance(x, ir.Register):
        into.add(id(x))
    elif isinstance(x, (ir.Intrinsic, ir.InvokeSubroutine)):
        for a in x.args:
            _collect_regs(a, into)
    elif isinstance(x, ir.ValueTuple):
        for v in x.values:
            _collect_regs(v, into)


def _prune_dead_phis(subs) -> None:
    """Drop phis not reachable (through phi args) from a real use — i.e. the
    frame stack-model phis, now that frame ops no longer consume them. Forward
    liveness: seed from ops / control / returns (NOT phi args), then propagate
    backward through phi arguments; keep only live phis."""
    live: set = set()
    phi_by_reg: dict = {}
    for sub in subs:
        for b in sub.body:
            for phi in b.phis:
                phi_by_reg[id(phi.register)] = phi
    for sub in subs:
        for b in sub.body:
            for op in b.ops:
                if isinstance(op, ir.Assignment):
                    _collect_regs(op.source, live)
                elif isinstance(op, ir.Assert):
                    _collect_regs(op.condition, live)
                elif isinstance(op, ir.IntrinsicOp):
                    _collect_regs(op.intrinsic, live)
            t = b.terminator
            if isinstance(t, ir.ConditionalBranch):
                _collect_regs(t.condition, live)
            elif isinstance(t, (ir.Switch, ir.GotoNth)):
                _collect_regs(t.value, live)
            elif isinstance(t, ir.SubroutineReturn):
                for r in t.result:
                    _collect_regs(r, live)
            elif isinstance(t, ir.ProgramExit):
                _collect_regs(t.result, live)
    work = list(live)
    while work:
        phi = phi_by_reg.get(work.pop())
        if phi is None:
            continue
        for pa in phi.args:
            if isinstance(pa.value, ir.Register) and id(pa.value) not in live:
                live.add(id(pa.value))
                work.append(id(pa.value))
    for sub in subs:
        for b in sub.body:
            b.phis = [phi for phi in b.phis if id(phi.register) in live]


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
    ``==`` mirrors the other operand, branch conditions are uint64."""
    reg_by_id: dict = {}
    uses: dict = {}

    def use(r, op, idx, args):
        if isinstance(r, ir.Register):
            reg_by_id[id(r)] = r
            uses.setdefault(id(r), []).append((op, idx, args))

    def note(vp):
        if isinstance(vp, (ir.Intrinsic, ir.InvokeSubroutine)):
            op = vp.op if isinstance(vp, ir.Intrinsic) else None
            for i, a in enumerate(vp.args):
                use(a, op, i, vp.args)

    for sub in subs:
        for b in sub.body:
            for o in b.ops:
                if isinstance(o, ir.Assignment):
                    note(o.source)
                elif isinstance(o, ir.IntrinsicOp):
                    note(o.intrinsic)
                elif isinstance(o, ir.Assert):
                    use(o.condition, "assert", 0, [o.condition])
            t = b.terminator
            if isinstance(t, ir.ConditionalBranch):
                use(t.condition, "__cond__", 0, [t.condition])

    for _ in range(6):
        changed = False
        for rid, r in reg_by_id.items():
            if r.ir_type != "?":
                continue
            inferred = {et for (op, i, args) in uses.get(rid, [])
                        if (et := _expected_type(op, i, args)) and et != "?"}
            if len(inferred) == 1:        # all uses agree -> safe to set
                r.ir_type = next(iter(inferred))
                changed = True
        if not changed:
            break


def _infer_returns(subs) -> None:
    """Set each subroutine's return types from its ``SubroutineReturn`` values
    (first typed value per position, across return sites)."""
    for sub in subs:
        if sub.is_main:
            continue
        rets = None
        for b in sub.body:
            t = b.terminator
            if isinstance(t, ir.SubroutineReturn):
                ts = [getattr(v, "ir_type", "?") for v in t.result]
                if rets is None:
                    rets = ts
                else:
                    rets = [a if a != "?" else b2 for a, b2 in zip(rets, ts)]
        if rets is not None:
            sub.returns = rets


def _unify_phi_types(subs) -> None:
    for _ in range(8):
        changed = False
        for sub in subs:
            for b in sub.body:
                for phi in b.phis:
                    if phi.register.ir_type != "?":
                        continue
                    ts = {a.value.ir_type for a in phi.args
                          if getattr(a.value, "ir_type", "?") != "?"}
                    if len(ts) == 1:
                        phi.register.ir_type = next(iter(ts))
                        changed = True
        if not changed:
            break
