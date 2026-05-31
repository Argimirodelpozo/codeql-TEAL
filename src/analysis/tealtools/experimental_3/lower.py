"""Lower an :class:`~tealtools.ssa.SSAProgram` into the Puya-shaped IR model.

``lower(prog) -> ir.Program``. This is the representational-parity step: our
SSA (blocks, phis, ``exit_stack``, opcode assignments, terminators) is
*transformed into* the Puya IR classes in :mod:`tealtools.experimental_3.ir`,
which then render themselves in the ``.ssa.slot.ir`` shape. Rendering is no
longer a bespoke printer — it falls out of the model.

Scope of this first pass: everything goes under a single ``main`` subroutine
(subroutine partitioning is a later tier; the model already supports it).
Constants and trivial single-predecessor phis are inlined; the type/field
tables are shared with :mod:`tealtools.experimental_3.puya_ir`.
"""
from __future__ import annotations

from . import ir
from ..block_args import to_block_args
from ..ssa import Const, Phi, SSAProgram, SSAVar, _TERMINATOR_OPS
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
    blocks = sorted(prog.blocks.values(), key=lambda b: (b.file, b.first_line))
    bid = {bb: i for i, bb in enumerate(blocks)}
    line2block = {bb.first_line: bb for bb in blocks}
    label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in prog.labels}

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

    # ---- registers: one per shown SSAVar + each real-join phi, named in
    # block order so block@0's values get the low numbers.
    regs: dict = {}
    ctr: dict = {}

    def _new_reg(prefix: str, ir_type: str) -> ir.Register:
        # Puya naming: name carries the allocation id (``tmp%5``); ``#version``
        # is the SSA version (always 0 here -- our SSA is already per-def).
        n = ctr.get(prefix, 0)
        ctr[prefix] = n + 1
        return ir.Register(f"{prefix}%{n}", 0, ir_type)

    def _is_real_phi(ph: Phi) -> bool:
        bb = ph.basic_block
        return bb is not None and len(bb.predecessors) > 1

    for bb in blocks:
        if len(bb.predecessors) > 1:
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                if ph not in regs:
                    regs[ph] = _new_reg("tmp", type_of(ph))
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock"):
                continue
            if (len(a.outputs) == 1 and not a.inputs
                    and getattr(a.outputs[0], "const_value", None) is not None):
                continue
            for o in a.outputs:
                if isinstance(o, SSAVar) and o not in regs:
                    regs[o] = _new_reg(_NAME_PREFIX.get(a.op, "tmp"),
                                       type_of(o, a.op, a.immediates))

    def reg(o) -> ir.Register:
        if o not in regs:
            regs[o] = _new_reg("v", type_of(o))
        return regs[o]

    def value(o, _seen=None):
        """Operand -> ir.Value, inlining consts + trivial single-pred phis."""
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
        succ = bb.successors
        t = term_assign(bb)
        op = t.op if t is not None else None
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

    # ---- build blocks
    out_blocks = []
    for bb in blocks:
        phis = []
        if len(bb.predecessors) > 1:
            params = list(form.params.get(bb, []))
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                i = params.index(ph) if ph in params else None
                args = []
                for pred in bb.predecessors:
                    e = form.edge(pred, bb)
                    val = (e.args[i] if (e is not None and i is not None
                                         and i < len(e.args)) else None)
                    args.append(ir.PhiArgument(value(val), bid[pred]))
                phis.append(ir.Phi(reg(ph), args))
        ops = []
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock"):
                continue
            if (len(a.outputs) == 1 and not a.inputs
                    and getattr(a.outputs[0], "const_value", None) is not None):
                continue
            args = [value(i) for i in a.inputs]
            imm = a.immediates.split() if a.immediates else []
            intr = ir.Intrinsic(a.op, imm, args)
            shown = [o for o in a.outputs if isinstance(o, SSAVar)]
            if a.op == "assert" and not shown:
                ops.append(ir.Assert(args[0] if args else ir.Undefined()))
            elif shown:
                ops.append(ir.Assignment([reg(o) for o in shown], intr))
            else:
                ops.append(ir.IntrinsicOp(intr))
        out_blocks.append(ir.BasicBlock(
            id=bid[bb], phis=phis, ops=ops,
            terminator=control(bb), comment=f"L{bb.first_line}",
        ))

    # Unify each phi's type from its arguments (fixpoint, for phi-of-phi
    # chains): a phi whose every typed argument agrees takes that type.
    for _ in range(8):
        changed = False
        for b in out_blocks:
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

    name = blocks[0].file.split("/")[-1] if blocks else "program"
    main = ir.Subroutine(id=name, parameters=[], returns=[],
                         body=out_blocks, is_main=True)
    return ir.Program(main=main, subroutines=[])
