"""Lower an :class:`~tealtools.ssa.SSAProgram` into the Puya-shaped IR model.

``lower(prog) -> ir.Program``. This is the representational-parity step: our
SSA (blocks, phis, ``exit_stack``, opcode assignments, terminators) is
*transformed into* the Puya IR classes in :mod:`tealtools.experimental_3.ir`,
which then render themselves in the ``.ssa.slot.ir`` shape.

Subroutine partitioning reuses :func:`tealtools.structure.analyze_structure`:
the routing + handler BBs become ``main``; each ``callsub``-reachable routine
becomes an ``ir.Subroutine``. Block ids and the ``tmp%N`` name counter restart
per subroutine (matching Puya). ``callsub`` becomes ``ir.InvokeSubroutine`` and
the block continues to the call's continuation; ``retsub`` becomes
``ir.SubroutineReturn``; ``proto`` is consumed into the signature.

Constants and trivial single-predecessor phis are inlined; the type/field
tables are shared with :mod:`tealtools.experimental_3.puya_ir`.
"""
from __future__ import annotations

from . import ir
from ..block_args import to_block_args
from ..ssa import Const, Phi, SSAProgram, SSAVar, _TERMINATOR_OPS
from ..structure import analyze_structure
from .puya_ir import (
    _BOOL_OPS, _BYTES_OPS, _COND_BRANCH, _NAME_PREFIX, _U64_OPS, _field_type,
)


def _const(cv: Const):
    if cv.kind == "uint64":
        try:
            return ir.UInt64Constant(int(cv.value))
        except ValueError:
            return ir.UInt64Constant(0)
    return ir.BytesConstant(cv.value)


def lower(prog: SSAProgram) -> ir.Program:
    form = to_block_args(prog)
    label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in prog.labels}

    # ---- partition into main (routing + handlers) + subroutines ----------
    struct = analyze_structure(prog)
    sub_of = {bb: s for s in struct.subroutines for bb in s.body}
    callsite = {cs.callsub_bb: cs for cs in struct.call_sites}

    def _key(bb):
        return (bb.file, bb.first_line)

    all_blocks = sorted(prog.blocks.values(), key=_key)
    main_blocks = [bb for bb in all_blocks if bb not in sub_of]
    groups = [("main", None, main_blocks)]
    for s in sorted(struct.subroutines, key=lambda s: _key(s.entry_bb)):
        gb = sorted(s.body, key=_key)
        groups.append((s.name or f"sub@L{s.entry_bb.first_line}", s, gb))

    # Global block ids (unambiguous across groups). Puya restarts block@0 per
    # subroutine; doing that here needs cross-routine edges (b/bz that leak
    # between partitions) ironed out first, so keep ids global for now and
    # only group the *rendering* into subroutine sections.
    bid = {bb: i for i, bb in enumerate(all_blocks)}
    line2block = {bb.first_line: bb for bb in all_blocks}

    # ---- typing --------------------------------------------------------
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

    # ---- registers: per-group `tmp%N` counters (restart per subroutine) ---
    regs: dict = {}
    ctr: dict = {}

    def _new_reg(prefix: str, ir_type: str) -> ir.Register:
        n = ctr.get(prefix, 0)
        ctr[prefix] = n + 1
        return ir.Register(f"{prefix}%{n}", 0, ir_type)

    def _is_real_phi(ph: Phi) -> bool:
        bb = ph.basic_block
        return bb is not None and len(bb.predecessors) > 1

    def _name_group(gb):
        ctr.clear()
        for bb in gb:
            if len(bb.predecessors) > 1:
                for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                    if ph not in regs:
                        regs[ph] = _new_reg("tmp", type_of(ph))
            for a in bb.assignments:
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

    def reg(o) -> ir.Register:
        if o not in regs:
            regs[o] = _new_reg("v", type_of(o))
        return regs[o]

    def value(o, _seen=None):
        seen = _seen if _seen is not None else set()
        while isinstance(o, Phi) and not _is_real_phi(o):
            b = o.basic_block
            if b is None or len(b.predecessors) != 1 or id(o) in seen:
                break
            seen.add(id(o))
            es = b.predecessors[0].exit_stack
            k = o.stack_index
            nxt = es[-k] if 0 < k <= len(es) else None
            if nxt is None:
                break
            o = nxt
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
        if op == "callsub":                       # call then continue
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
            if a.op == "callsub":
                cs = callsite.get(bb)
                target = (cs.target_name if cs and cs.target_name
                          else (a.immediates or "?"))
                invoke = ir.InvokeSubroutine(target, [value(i) for i in a.inputs])
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

    # ---- build each group into an ir.Subroutine -------------------------
    subs = []
    for gname, s, gb in groups:
        _name_group(gb)
        body = [_build_block(bb) for bb in gb]
        if s is None:
            file = all_blocks[0].file.split("/")[-1] if all_blocks else "program"
            subs.append(ir.Subroutine(id=file, parameters=[], returns=[],
                                      body=body, is_main=True))
        else:
            nargs, nrets = _proto_io(s.entry_bb)
            params = [ir.Parameter(ir.Register(f"p%{i}", 0, "?"))
                      for i in range(nargs)]
            subs.append(ir.Subroutine(id=gname, parameters=params,
                                      returns=["?"] * nrets, body=body))

    # phi-type unification (fixpoint, for phi-of-phi chains)
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

    main = next(sub for sub in subs if sub.is_main)
    return ir.Program(main=main, subroutines=[s for s in subs if not s.is_main])


def _proto_io(entry_bb):
    """``(nargs, nreturns)`` from the ``proto`` op of a subroutine entry BB,
    or ``(0, 0)`` if absent."""
    for a in entry_bb.assignments:
        if a.op == "proto":
            toks = (a.immediates or "").split()
            if len(toks) >= 2:
                try:
                    return int(toks[0]), int(toks[1])
                except ValueError:
                    break
    return 0, 0
