"""Forward a scratch ``load N`` to the value its ``store N``s wrote.

HAZARD: MUST-semantics — both passes require EVERY may-influencing store from
the ``scratch_stores`` annotation to agree, and bail on any store they cannot
resolve. Accepting a majority, or ignoring an unresolved store, forwards a
value the load may never actually hold."""
from __future__ import annotations

from ..ssa import Const, SSAProgram, SSAVar
from ..ssa.scratch_influence import UNINIT_STORE, UNKNOWN_STORE

# The AVM zero-initialises scratch, so the entry pseudo-definition is a
# precisely-known uint64 0 and counts as one more store that must agree.
# UNKNOWN (dynamic ``stores`` / unresolvable operand) agrees with nothing.
_UNINIT_CONST = Const("int", "0")


def propagate_scratch_constants(prog: SSAProgram) -> None:
    # Fixed point: a load resolved to K can flow into another store, whose load
    # then resolves, and so on.
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
    """Forward loads to their agreed source SSAVar; returns how many were forwarded.

    HAZARD: must iterate to a fixed point. One sweep resolves only one level of
    a chained round-trip (``store 2; load 2; store 3; load 3``), which leaves the
    value web half-forwarded."""
    total = 0
    while True:
        forwarded = _forward_scratch_loads_once(prog)
        total += forwarded
        if not forwarded:
            return total


def _forward_scratch_loads_once(prog: SSAProgram) -> int:
    """One sweep; returns the loads whose consumers were ACTUALLY rewired.

    HAZARD: the count must reflect real change or the fixpoint loop above never
    terminates — a load with nothing left to rewire would report progress forever."""
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
            # Sentinel keys (UNINIT/UNKNOWN) resolve to no var — there is no
            # SSAVar identity to forward across them, so bail.
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
