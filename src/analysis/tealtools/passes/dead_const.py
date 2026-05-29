"""Dead-constant elimination for SSAProgram.

Inlines resolved literals into every consumer's input list, then drops the
now-orphan const SSAVars / Phis and any Assignment whose outputs are all dead.
Conservative: only touches values with ``const_value`` set; never drops
control-flow terminators or the topmost-stack value at a ``return``.

Bridged from ``SSAProgram.eliminate_dead_constants`` (which keeps the
idempotency guard + the ``propagate_constants`` precondition + state flag).
"""
from __future__ import annotations

from ..ssa import Phi, SSAProgram, SSAVar
from ..ssa.models import _TERMINATOR_OPS


def eliminate_dead_constants(prog: SSAProgram) -> None:
    def _resolve(o):
        if isinstance(o, (SSAVar, Phi)) and o.const_value is not None:
            return o.const_value
        return o

    # Pass 1: replace every const-resolvable reference with its literal.
    for a in prog.assignments:
        a.inputs = [_resolve(i) for i in a.inputs]
    for ph in prog.phis.values():
        ph.args = [_resolve(arg) for arg in ph.args]

    # Pass 2: recompute structural reference sets.
    ref_vars: set[SSAVar] = set()
    ref_phis: set[Phi] = set()
    for a in prog.assignments:
        for i in a.inputs:
            if isinstance(i, SSAVar):
                ref_vars.add(i)
            elif isinstance(i, Phi):
                ref_phis.add(i)
    for ph in prog.phis.values():
        for arg in ph.args:
            if isinstance(arg, SSAVar):
                ref_vars.add(arg)
            elif isinstance(arg, Phi):
                ref_phis.add(arg)

    # Pass 2b: pin the topmost-stack SSAVar at every ``return`` op (the AVM
    # exit value has no SSA consumer, so without this it'd be dropped).
    returned_vars: set[SSAVar] = set()
    for bb in prog.blocks.values():
        ret_idx = None
        for i, a in enumerate(bb.assignments):
            if a.op == "return":
                ret_idx = i
                break
        if ret_idx is None:
            continue
        for a in reversed(bb.assignments[:ret_idx]):
            if a.outputs:
                for v in a.outputs:
                    if isinstance(v, SSAVar):
                        returned_vars.add(v)
                break

    # Pass 3: identify dead constant SSAVars / Phis.
    dead_vars = {
        v for v in prog.vars.values()
        if v.const_value is not None
        and v not in ref_vars
        and v not in returned_vars
    }
    dead_phis = {
        ph for ph in prog.phis.values()
        if ph.const_value is not None and ph not in ref_phis
    }

    # Pass 4: assignments whose every output is dead are dropped (terminators
    # are never dead — they have flow-graph side effects). id() membership
    # because Assignment is an unfrozen, unhashable dataclass.
    dead_assignment_ids: set[int] = {
        id(a) for a in prog.assignments
        if a.outputs
        and all(o in dead_vars for o in a.outputs)
        and a.op not in _TERMINATOR_OPS
    }
    for v in dead_vars:
        v.defined_by = None

    # Pass 5: commit removals.
    prog.vars = {k: v for k, v in prog.vars.items() if v not in dead_vars}
    prog.phis = {k: ph for k, ph in prog.phis.items() if ph not in dead_phis}
    prog.assignments = [a for a in prog.assignments if id(a) not in dead_assignment_ids]
    for bb in prog.blocks.values():
        bb.assignments = [a for a in bb.assignments if id(a) not in dead_assignment_ids]
        bb.phis = [ph for ph in bb.phis if ph not in dead_phis]
