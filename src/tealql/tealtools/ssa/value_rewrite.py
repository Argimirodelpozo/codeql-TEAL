"""Copy-propagate pure stack-shuffle outputs (``dup``, ``swap``, …) into their
consumers, marking the shuffle assignments ``.shuffled`` instead of deleting them."""
from __future__ import annotations

from ..ssa import (
    Assignment,
    Operand,
    SSAProgram,
    SSAVar,
    _STACK_SHUFFLE_OPS,
    _shuffle_mapping,
)


def propagate_stack_shuffles(prog: SSAProgram) -> None:
    redirect: dict[SSAVar, Operand] = {}
    shuffle_assigns: list[Assignment] = []
    for a in prog.assignments:
        if a.op not in _STACK_SHUFFLE_OPS:
            continue
        mapping = _shuffle_mapping(a)
        if mapping is None:
            continue
        shuffle_assigns.append(a)
        for out_idx, in_idx in enumerate(mapping):
            out = a.outputs[out_idx]
            if isinstance(out, SSAVar):
                redirect[out] = a.inputs[in_idx]

    if not redirect:
        return

    # Flatten shuffle-of-shuffle chains to the deepest non-shuffle source.
    def _resolve(o: Operand) -> Operand:
        seen: set[SSAVar] = set()
        while isinstance(o, SSAVar) and o in redirect:
            if o in seen:
                break  # defensive: cycles shouldn't exist on valid TEAL
            seen.add(o)
            o = redirect[o]
        return o

    final: dict[SSAVar, Operand] = {v: _resolve(v) for v in redirect}

    for a in prog.assignments:
        a.inputs = [final.get(i, i) if isinstance(i, SSAVar) else i
                    for i in a.inputs]
    for ph in prog.phis.values():
        ph.args = [final.get(arg, arg) if isinstance(arg, SSAVar) else arg
                   for arg in ph.args]

    for a in shuffle_assigns:
        a.shuffled = True

    # HAZARD: rebuild `.uses` from live reads only. The rewrite above changed
    # which var each consumer reads, and the now-`.shuffled` ops are no longer
    # live readers of their own inputs; anything that walks `.uses` (range_assert
    # dominance, DCE, byte_taint) reasons over the wrong set if a stale dead use
    # survives. Phi args are not op-uses — that matches construction.
    touched: dict = {}
    for a in prog.assignments:
        for op in (*a.inputs, *a.outputs):
            if hasattr(op, "uses"):
                touched[id(op)] = op
    for ph in prog.phis.values():
        touched[id(ph)] = ph
    for op in touched.values():
        op.uses = []
    for a in prog.assignments:
        if a.shuffled:
            continue
        for op in a.inputs:
            if hasattr(op, "uses"):
                op.uses.append(a)
