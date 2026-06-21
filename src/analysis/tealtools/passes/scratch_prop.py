"""Scratch-slot value/constant forwarding for SSAProgram.

Both consume the ``scratch_stores`` graph annotation (per ``load N``, the
may-influencing ``store N`` value-SSAVar keys produced by
:func:`tealtools.ssa.scratch_influence.compute_scratch_influence`):

- :func:`propagate_scratch_constants` — resolve a load to a literal when every
  influencing store wrote the same compile-time constant (must-semantics).
- :func:`propagate_scratch_values` — generalise to arbitrary SSA values: when
  every influencing store wrote the same SSAVar, rewire the load's consumers
  to reference it directly.

Bridged from ``SSAProgram.propagate_scratch_*``, which keep the idempotency
guards and pass-ordering preconditions.
"""
from __future__ import annotations

from ..ssa import Const, SSAProgram, SSAVar


def propagate_scratch_constants(prog: SSAProgram) -> None:
    # Iterate to fixed point: a load resolved to K can in turn flow back into
    # another store, whose load can then resolve, and so on.
    changed = True
    while changed:
        changed = False
        for n in prog._graph.nodes:
            stores = prog._graph.nodes[n].get("scratch_stores")
            if not stores:
                continue
            # The load op `n` has a single output SSAVar at outIdx=1.
            load_var = prog.var(n.location.file, n.location.start_line, 1)
            if load_var is None or load_var.const_value is not None:
                continue
            # Look up each store's consumed-value SSAVar by its key.
            resolved: list[Const] = []
            ok = True
            for sv_file, sv_line, sv_idx in stores:
                src = prog.var(sv_file, sv_line, sv_idx)
                if src is None or src.const_value is None:
                    ok = False
                    break
                resolved.append(src.const_value)
            if ok and resolved and all(c == resolved[0] for c in resolved):
                load_var.const_value = resolved[0]
                changed = True


def propagate_scratch_values(prog: SSAProgram) -> int:
    """Returns the number of loads forwarded. Mutates the SSA in place."""
    forwarded = 0
    for n in prog._graph.nodes:
        stores = prog._graph.nodes[n].get("scratch_stores")
        if not stores:
            continue
        load_var = prog.var(n.location.file, n.location.start_line, 1)
        if load_var is None:
            continue
        sources: list[SSAVar] = []
        ok = True
        for sv_file, sv_line, sv_idx in stores:
            src = prog.var(sv_file, sv_line, sv_idx)
            if src is None:
                ok = False
                break
            sources.append(src)
        if not ok or not sources:
            continue
        first = sources[0]
        if not all(s is first for s in sources):
            continue
        if load_var is first:
            continue
        for cons in list(load_var.uses):
            for i, inp in enumerate(cons.inputs):
                if inp is load_var:
                    cons.inputs[i] = first
                    first.uses.append(cons)
        for phi in prog.phis.values():
            for i, arg in enumerate(phi.args):
                if arg is load_var:
                    phi.args[i] = first
        load_var.uses = []
        forwarded += 1
    return forwarded
