"""Lift an :class:`~tealtools.ssa.SSAProgram` into the Puya-shaped IR model.

``lift(prog) -> ir.Program``. This *raises* abstraction (the decompiler
direction): our stack-machine TEAL SSA — frame slots, scratch, stack shuffles —
becomes the value-based, typed, subroutine IR of
:mod:`tealtools.WIP_lift2puyaIR.ir`, which self-renders in the ``.ssa.slot.ir``
shape. (Puya itself *lowers* the other way: its AST → IR → TEAL.)

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
are shared with :mod:`tealtools.WIP_lift2puyaIR.puya_ir`.
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
    _multi_out_type,
)

_FRAME_OPS = frozenset({"frame_dig", "frame_bury"})


def _const(cv: Const):
    # SSA integer consts carry kind "int" (not "uint64"); without this they all
    # fell through to BytesConstant(decimal-string) -- rendered verbatim so it
    # looked right, but semantically a uint64 stored as bytes (Puya wants `Nu`).
    if cv.kind == "int":
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


_UINT64_MAX = (1 << 64) - 1


def _range_note(local_id: str, rng) -> str | None:
    """A compact ``// `` annotation for an :class:`IntRange`, or ``None`` when
    the range is the full uint64 domain (uninformative). The uint64 ceiling is
    rendered as an open ``>=`` floor rather than the 20-digit max."""
    lo, hi = rng.lo, rng.hi
    if lo <= 0 and hi >= _UINT64_MAX:
        return None
    if lo == hi:
        return f"{local_id} = {lo}"
    if hi >= _UINT64_MAX:
        return f"{local_id} >= {lo}"
    if lo <= 0:
        return f"{local_id} <= {hi}"
    return f"{lo} <= {local_id} <= {hi}"


def _len_note(local_id: str, t) -> str | None:
    """``len(x) = 8`` / ``len(x) <= 20`` / ``2 <= len(x) <= 4096`` from a bytes
    type's exact ``byte_length`` or its ``byte_length_range``."""
    bl = getattr(t, "byte_length", None)
    if bl is not None:
        return f"len({local_id}) = {bl}"
    r = getattr(t, "byte_length_range", None)
    if r is None:
        return None
    if r.lo == r.hi:
        return f"len({local_id}) = {r.lo}"
    if r.lo <= 0:
        return f"len({local_id}) <= {r.hi}"
    return f"{r.lo} <= len({local_id}) <= {r.hi}"


def _val_note(local_id: str, t, cap: int = 40) -> str | None:
    """``x = N`` / ``lo <= x <= hi`` from a bytes type's bigint
    ``int_value_range`` (bytemath). Multi-hundred-digit bounds collapse to
    ``<N-bit>`` so the line stays readable."""
    r = getattr(t, "int_value_range", None)
    if r is None:
        return None

    def _s(n: int) -> str:
        s = str(n)
        return s if len(s) <= cap else f"<{n.bit_length()}-bit>"

    if r.lo == r.hi:
        return f"{local_id} = {_s(r.lo)}"
    return f"{_s(r.lo)} <= {local_id} <= {_s(r.hi)}"


def lift(prog: SSAProgram) -> ir.Program:
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

    # Global block ids. Puya restarts block@0 per subroutine, but that's not
    # safe here: structure.py's partition has ~28 cross-routine branch edges
    # (tail-calls / compiler-shared epilogues that don't belong to one
    # routine), so a per-subroutine-local id would silently mis-target those
    # gotos. Global ids keep control flow correct; per-sub numbering needs the
    # routines to be closed CFG regions, which is a structure.py concern.
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
        if op == "load":
            # A scratch load is typed by what was stored into the slot, via
            # the reaching-def (``_ssa_type`` resolves it through
            # ``load_stores`` with a depth guard); the slot itself carries no
            # type, which is why the plain checks above leave it ``?``.
            rt = _ssa_type(o)
            if rt != "?":
                return rt
        return "?"

    regs: dict = {}
    ctr: dict = {}
    frame_map: dict = {}              # SSAVar (frame_dig out[0]) -> Register
    local_regs: dict = {}            # (gname, slot) -> Register (k<0 bury fallback)
    local_ver: dict = {}             # (gname, slot) -> next version counter
    bury_target: dict = {}           # id(frame_bury assignment) -> versioned Register
    final_locals: dict = {}          # gname -> {slot: final versioned Register}
    shuffle_src: dict = {}           # SSAVar (shuffle output) -> source operand
    cur_gname = "main"
    cur_nret = 0                     # proto return count of the group being built

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

    def _range_comment(outs) -> str | None:
        """``// v0 = 1, len(v1) = 8`` style note for the ranged outputs of an
        assignment / phi. uint64 vars carry an ``IntRange`` (range_arith /
        range_assert); bytes vars carry a byte length and/or a bigint value
        range on their type (byte_lengths / bytemath). ``None`` when nothing
        informative is annotated."""
        parts = []
        for o in outs:
            lid = reg(o).local_id
            rng = getattr(o, "range", None)
            if rng is not None:
                note = _range_note(lid, rng)
                if note:
                    parts.append(note)
            t = getattr(o, "type", None)
            if t is not None and getattr(t, "kind", None) == "bytes":
                for note in (_len_note(lid, t), _val_note(lid, t)):
                    if note:
                        parts.append(note)
        return ", ".join(parts) if parts else None

    def _setup_frame(gb, params):
        # A non-negative frame slot is a subroutine *local*. Puya's compiler
        # colours disjoint-lifetime locals onto one slot, so a slot may hold
        # values of different types over its life -- not valid SSA as a single
        # register. Version it: each `frame_bury` opens a new version, each
        # `frame_dig` reads the version reaching it (block order; a true merge
        # of differing versions would need a phi -- TODO, absent in the slot-
        # colouring patterns seen so far). Negative slots are params (and the
        # rare `frame_bury -k` keeps its old single-register fallback).
        nargs = len(params)
        cur: dict = {}               # slot -> current versioned Register

        def _fresh(slot: int) -> ir.Register:
            key = (cur_gname, slot)
            v = local_ver.get(key, 0)
            local_ver[key] = v + 1
            return ir.Register(f"l%{slot}", v, "?")

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
                        r = cur.get(k)
                        if r is None:                # read-before-write local
                            r = cur[k] = _fresh(k)
                        frame_map[out0] = r
                    # fat-frame passthrough: dig pushes the slot on top, the rest
                    # of the stack re-emerges shifted (out[i] = in[i-1]); route it
                    # so later consumers of those slots resolve to the real value.
                    for i in range(1, len(a.outputs)):
                        o = a.outputs[i]
                        if isinstance(o, SSAVar) and i - 1 < len(a.inputs):
                            shuffle_src[o] = a.inputs[i - 1]
                elif a.op == "frame_bury" and a.inputs:
                    k = _imm0(a)
                    if k is not None and k >= 0:
                        bury_target[id(a)] = cur[k] = _fresh(k)
                    # bury pops the top into the slot; the rest passes through
                    # shifted the other way (out[i] = in[i+1]).
                    for i in range(len(a.outputs)):
                        o = a.outputs[i]
                        if isinstance(o, SSAVar) and i + 1 < len(a.inputs):
                            shuffle_src[o] = a.inputs[i + 1]
        final_locals[cur_gname] = dict(cur)      # final reg per written slot

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
                nssa = sum(isinstance(o, SSAVar) for o in a.outputs)
                for idx, o in enumerate(a.outputs):
                    if not isinstance(o, SSAVar):
                        continue
                    # idx is the top-first output slot; multi-result ops
                    # (get_ex / params / box / addw…) type their slots
                    # individually -- type_of can't tell them apart.
                    mt = _multi_out_type(a.op, a.immediates, idx) if nssa > 1 else None
                    rt = mt or type_of(o, a.op, a.immediates)
                    if o not in regs:
                        regs[o] = _new_reg(pfx, rt)
                    elif regs[o].ir_type == "?" and rt != "?":
                        # already registered untyped by an earlier cross-group
                        # reference (a tail-call / shared-epilogue edge reaches
                        # value() before this, the defining, group is named);
                        # now that we know its op, fix the type in place.
                        regs[o].ir_type = rt

    def value(o, _seen=None):
        seen = _seen if _seen is not None else set()
        while True:
            if isinstance(o, (SSAVar, Phi)) and o in frame_map:
                break                            # param / local / callsub-return reg
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
        if op == "retsub":
            # A retsub returns to its caller. Its raw-CFG successors are the
            # callers' continuations (interprocedural return edges), but each
            # caller already reaches its own continuation via its callsub ->
            # Goto(continuation). So model retsub as a value return, NOT a
            # goto / goto_nth into the callers — the latter, with >1 caller,
            # had no selector and rendered as `goto_nth undefined`.
            #
            # The N returns are frame slots 0..N-1. A sub that *buries* its
            # return into the slot (frame_bury 0) leaves the slot's current
            # value there, not on the exit stack — so prefer the final slot
            # local; only fall back to the (bottom-first) exit-stack slice for
            # returns that were left on the stack.
            slots = final_locals.get(cur_gname, {})
            es = bb.exit_stack or []
            rets = []
            for j in range(cur_nret):
                if j in slots:
                    rets.append(slots[j])                  # buried into the slot
                elif len(es) >= cur_nret - j:
                    rets.append(value(es[-cur_nret + j]))  # left on the stack
            return ir.SubroutineReturn(rets)
        succ = [s for s in bb.successors if s in bid]
        if not succ:
            if op == "return":
                v = (value(bb.exit_stack[-1]) if bb.exit_stack
                     else ir.UInt64Constant(0))
                return ir.ProgramExit(v)
            if op == "err":
                return ir.Fail()
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
                phis.append(ir.Phi(reg(ph), args, comment=_range_comment([ph])))
        ops = []
        for a in bb.assignments:
            if _is_routed_shuffle(a):
                continue                            # const shuffle routed to source
            if a.op == "frame_dig":
                continue                            # a param/local read (no op)
            if a.op == "frame_bury":
                slot = _imm0(a)
                if slot is not None and a.inputs:
                    # versioned local (slot >= 0); k < 0 keeps the single-reg fallback
                    tgt = bury_target.get(id(a)) or _local(slot)
                    ops.append(ir.Assignment([tgt], value(a.inputs[0])))
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
                outs = call_results.get(bb)      # caller-local return registers
                if outs:
                    ops.append(ir.Assignment(list(outs), invoke))
                else:
                    ops.append(ir.IntrinsicOp(invoke))
                continue
            if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock",
                                                   "proto"):
                continue
            if (len(a.outputs) == 1 and not a.inputs
                    and getattr(a.outputs[0], "const_value", None) is not None):
                continue
            args = [value(i) for i in a.inputs]
            intr = ir.Intrinsic(a.op, a.immediates.split() if a.immediates else [],
                                args, line=a.location.line)
            shown = [o for o in a.outputs if isinstance(o, SSAVar)]
            if a.op == "assert" and not shown:
                ops.append(ir.Assert(args[0] if args else ir.Undefined()))
            elif shown:
                ops.append(ir.Assignment([reg(o) for o in shown], intr,
                                         comment=_range_comment(shown)))
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
            if isinstance(arg, (SSAVar, Phi)):
                rt = reg(arg).ir_type        # IR-level type is the complete one
                if rt != "?":                # (render + use / state / copy-load)
                    return rt
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

    # Inter-procedural return wiring. A callsub's continuation receives the
    # callee's return value(s). In the raw CFG that value is a phi whose only
    # predecessor is the callee's retsub block, so it would resolve into the
    # callee's register space -- a different Puya subroutine, hence "undefined"
    # in the caller. Bind it to the InvokeSubroutine's result instead: alias the
    # continuation's top-of-stack return phi(s) to a caller-local result reg.
    call_results: dict = {}          # callsub_bb -> [result Register], declared order
    for cs in struct.call_sites:
        cont, entry = cs.continuation_bb, cs.target_entry
        if cont is None or entry is None:
            continue
        nret = _proto_io(entry)[1]
        if nret <= 0:
            continue
        by_idx = {ph.stack_index: ph for ph in cont.phis}
        outs = []
        for j in range(nret):                # j: declared order; stack_index 1 = top
            ph = by_idx.get(nret - j)
            r = reg(ph) if ph is not None else _new_reg("cr", "?")
            if ph is not None:
                frame_map[ph] = r            # consumers resolve to the result reg
            outs.append(r)
        call_results[cs.callsub_bb] = outs

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
        cur_nret = nrets
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

    def _infer_state_types():
        """Type global / local state read *values* from the contract's own put
        schema: a value is whatever was put to its (constant) key. Runs after
        param / return inference, so a value put straight from a typed param or
        field resolves -- it reads each put value operand's *final* register
        type (top-first inputs: value at [0], key at [1]). A key with
        conflicting put types is left unknown. A read's key is always
        ``inputs[0]``; ``*_get_ex`` keeps did_exist at output 0 and the value
        at output 1, a plain ``*_get`` its sole output."""
        key_types: dict = {}
        for a in prog.assignments:
            if a.op in ("app_global_put", "app_local_put") and len(a.inputs) >= 2:
                key, v = _const_key(a.inputs[1]), a.inputs[0]
                if key is None or not isinstance(v, (SSAVar, Phi)):
                    continue
                vt = reg(v).ir_type
                if vt and vt != "?":
                    key_types.setdefault(key, set()).add(vt)
        key_types = {k: next(iter(s)) for k, s in key_types.items() if len(s) == 1}
        if not key_types:
            return
        for a in prog.assignments:
            if a.op in ("app_global_get", "app_local_get"):
                val = a.outputs[0] if a.outputs else None
            elif a.op in ("app_global_get_ex", "app_local_get_ex"):
                val = a.outputs[1] if len(a.outputs) > 1 else None
            else:
                continue
            if not isinstance(val, (SSAVar, Phi)):
                continue
            r = reg(val)
            if r.ir_type == "?":
                k = _const_key(a.inputs[0]) if a.inputs else None
                if k in key_types:
                    r.ir_type = key_types[k]

    def _propagate_copy_load_types():
        """Close the remaining untyped registers at the IR level, to a
        fixpoint: a copy / local store (``let l%N = <reg>``) takes its source
        register's type, and a scratch ``(load N)`` takes the type stored to
        its slot (via the reaching-def ``load_stores``). Iterated because a
        typed load feeds a copy that feeds another load. Runs last, after
        param / return / state inference have typed the leaves."""
        def _src_type(v):
            if isinstance(v, ir.Register):
                return v.ir_type
            if isinstance(v, ir.UInt64Constant):
                return "uint64"
            if isinstance(v, ir.BytesConstant):
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
            for sub in subs:
                for bb in sub.body:
                    for op in bb.ops:
                        if (isinstance(op, ir.Assignment) and len(op.targets) == 1
                                and op.targets[0].ir_type == "?"):
                            st = _src_type(op.source)
                            if st and st != "?":
                                op.targets[0].ir_type = st
                                changed = True
            for a in prog.assignments:
                if a.op != "load" or not a.outputs:
                    continue
                out = a.outputs[0]
                if not isinstance(out, (SSAVar, Phi)) or reg(out).ir_type != "?":
                    continue
                tys = {reg(s).ir_type for s in load_stores.get(out, ())
                       if isinstance(s, (SSAVar, Phi))} - {"?"}
                if len(tys) == 1:
                    reg(out).ir_type = next(iter(tys))
                    changed = True

    # Global type fixpoint. The register-typing passes feed each other: a typed
    # caller arg types a callee param (_infer_params_from_callers); a typed
    # param types its frame reads; a typed value types the slots it's stored to
    # and the loads of them (_propagate_copy_load_types); a put types the
    # matching get (_infer_state_types); uses and phi args pin the rest. Run
    # them together until no register changes. Every pass is monotonic (only
    # `?` -> a concrete type), so the untyped count strictly decreases and this
    # terminates.
    def _untyped():
        n = 0
        for sub in subs:
            for pp in sub.parameters:
                n += pp.register.ir_type == "?"
            n += sum(r == "?" for r in sub.returns)
            for bb in sub.body:
                for phi in bb.phis:
                    n += phi.register.ir_type == "?"
                for op in bb.ops:
                    if isinstance(op, ir.Assignment):
                        n += sum(t.ir_type == "?" for t in op.targets)
        return n

    name2sub = {s.id: s for s in subs if not s.is_main}

    def _unify_call_returns():
        # A callsite's result register and the callee's declared return are the
        # same value -- unify their AVM types both ways, and pin the callee's
        # SubroutineReturn value register too, so the callee types up internally.
        for cs_bb, regs in call_results.items():
            cs = callsite.get(cs_bb)
            callee = name2sub.get(cs.target_name) if cs else None
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
                        if isinstance(t, ir.SubroutineReturn) and pos < len(t.result):
                            rv = t.result[pos]
                            if isinstance(rv, ir.Register) and rv.ir_type == "?":
                                rv.ir_type = ret

    prev = -1
    while prev != _untyped():
        prev = _untyped()
        _infer_types_from_uses(subs)
        _infer_params_from_callers(sub_pairs)
        _unify_phi_types(subs)
        _infer_state_types()
        _propagate_copy_load_types()
        _infer_returns(subs)
        _unify_call_returns()

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
            if isinstance(t, ir.SubroutineReturn):
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
