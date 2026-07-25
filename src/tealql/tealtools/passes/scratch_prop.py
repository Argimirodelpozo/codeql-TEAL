"""Scratch-slot value/constant forwarding for SSAProgram.

Both consume the ``scratch_stores`` graph annotation (per ``load N``, the
may-influencing ``store N`` value-SSAVar keys produced by
:func:`tealql.tealtools.ssa.scratch_influence.compute_scratch_influence`):

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
from ..ssa.scratch_influence import UNINIT_STORE, UNKNOWN_STORE

# The AVM zero-initialises scratch: the entry pseudo-definition has the
# precisely-known value uint64 0, so const-prop treats it as one more store
# that must agree with the rest. UNKNOWN (dynamic ``stores`` / unresolvable
# operand) can never agree with anything.
_UNINIT_CONST = Const("int", "0")


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
                if (sv_file, sv_line, sv_idx) == UNINIT_STORE:
                    resolved.append(_UNINIT_CONST)
                    continue
                if (sv_file, sv_line, sv_idx) == UNKNOWN_STORE:
                    ok = False
                    break
                src = prog.var(sv_file, sv_line, sv_idx)
                if src is None or src.const_value is None:
                    ok = False
                    break
                resolved.append(src.const_value)
            if ok and resolved and all(c == resolved[0] for c in resolved):
                load_var.const_value = resolved[0]
                changed = True


def propagate_scratch_values(prog: SSAProgram) -> int:
    """Returns the number of loads forwarded. Mutates the SSA in place.

    Iterates to a FIXED POINT, like its ``propagate_scratch_constants`` sibling:
    a chained round-trip (``store 2; load 2; store 3; load 3``) only resolves one
    level per sweep, and the sweep order over ``_graph.nodes`` decides which
    level that is. A single sweep therefore left the value web half-forwarded and
    made ``run_all_passes`` NON-idempotent — the second run kept forwarding, and
    a chain of depth N needed N runs to converge, contradicting both this
    function's "a second call finds nothing further" claim and orchestrate's
    "running run_all_passes twice is a no-op"."""
    total = 0
    while True:
        forwarded = _forward_scratch_loads_once(prog)
        total += forwarded
        if not forwarded:
            return total


def _forward_scratch_loads_once(prog: SSAProgram) -> int:
    """One sweep. Returns loads whose consumers were ACTUALLY rewired — the
    count must reflect real change or the fixpoint loop above never terminates
    (a load with nothing left to rewire would keep reporting progress)."""
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
            # Sentinel keys (UNINIT/UNKNOWN) resolve to no var → bail: there is
            # no SSAVar identity to forward across an uninitialised or unknown
            # reaching definition.
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
        rewired = False
        for cons in list(load_var.uses):
            for i, inp in enumerate(cons.inputs):
                if inp is load_var:
                    cons.inputs[i] = first
                    first.uses.append(cons)
                    rewired = True
        for phi in prog.phis.values():
            for i, arg in enumerate(phi.args):
                if arg is load_var:
                    phi.args[i] = first
                    rewired = True
        load_var.uses = []
        if rewired:
            forwarded += 1
    return forwarded
