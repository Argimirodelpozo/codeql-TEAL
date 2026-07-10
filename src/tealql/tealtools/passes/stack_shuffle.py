"""Copy-propagation of pure stack-shuffle opcode outputs into consumers.

For each shuffle op (``_STACK_SHUFFLE_OPS``), :func:`_shuffle_mapping` gives
the per-output source input; each output SSAVar is rewritten in every consumer
(``Assignment.inputs`` and ``Phi.args``) to read the source directly, with
shuffle-of-shuffle chains flattened in one hop. The shuffle assignments are
marked ``.shuffled`` so :meth:`Assignment.functional` renders them as ``// …``
comments.

Bridged from ``SSAProgram.propagate_stack_shuffles`` (which keeps the
idempotency guard + flag). Must run before ``materialize_phis`` — phi args are
``list[SSAVar | Phi]`` until materialisation.
"""
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
    # Step 1: collect shuffle assignments + the per-output redirect from each
    # output SSAVar to its source operand.
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

    # Step 2: flatten shuffle-of-shuffle chains so each output resolves to its
    # deepest non-shuffle source in one hop.
    def _resolve(o: Operand) -> Operand:
        seen: set[SSAVar] = set()
        while isinstance(o, SSAVar) and o in redirect:
            if o in seen:
                break  # defensive: cycles shouldn't exist on valid TEAL
            seen.add(o)
            o = redirect[o]
        return o

    final: dict[SSAVar, Operand] = {v: _resolve(v) for v in redirect}

    # Step 3: rewrite every consumer (Assignment.inputs and Phi.args).
    for a in prog.assignments:
        a.inputs = [final.get(i, i) if isinstance(i, SSAVar) else i
                    for i in a.inputs]
    for ph in prog.phis.values():
        ph.args = [final.get(arg, arg) if isinstance(arg, SSAVar) else arg
                   for arg in ph.args]

    # Step 4: mark the shuffle assignments (they stay in the IR; the flag
    # drives the ``// …`` prefix in Assignment.functional).
    for a in shuffle_assigns:
        a.shuffled = True

    # Step 5: restore the `.uses` invariant. Step 3 changed which var each
    # consumer reads, and the shuffle ops are now DEAD (`.shuffled`) — their
    # outputs were redirected away, so they are no longer LIVE readers of their
    # own inputs either. `.uses` must reflect only live reads, or a consumer that
    # walks it (e.g. `range_assert`'s dominance check, which would otherwise see a
    # stale dead-`dup` use and refuse to tighten an asserted-then-dup'd value; DCE;
    # byte_taint) reasons over the wrong set. Rebuild from current, non-shuffle
    # assignment inputs (phi args are not op-uses — matches construction). Cheap:
    # only runs when some redirect happened.
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
