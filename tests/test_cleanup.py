"""Regression tests for the isolated presentation cleanup.

Guards the phi-leaf liveness bug: a var consumed only as a phi argument
has an empty ``uses`` list (``uses`` tracks assignment consumers, not
phi-arg references), so cleanup must not treat it as dead and remove its
producer — otherwise the phi (and every materialised copy) ends up
referencing an undefined SSAVar.

Exercised on xgov (its constant-stack unroll produces many phis whose
leaves are concat/op outputs with empty ``uses``). Skips if unavailable.
"""
from pathlib import Path

import pytest

XGOV = Path(__file__).resolve().parent / "contracts/xgov"


def _prog():
    if not XGOV.exists():
        pytest.skip("xgov fixture not present")
    from tealql.tealtools.ssa import SSAProgram
    # A construction failure IS a test failure — never skip on it.
    return SSAProgram(str(XGOV))


def _ssavar_defs(prog):
    from tealql.tealtools.ssa import SSAVar
    return {
        (o.file, o.line, o.index)
        for a in prog.assignments for o in a.outputs
        if isinstance(o, SSAVar)
    }


class TestCleanupPhiLeaf:
    def test_cleanup_keeps_phi_referenced_producers(self):
        from tealql.tealtools.ssa import SSAVar
        from tealql.tealtools.analysis import DerivedProfile, derived_program
        from tealql.tealtools.ssa.presentation import cleanup_unused_ssavars
        p = _prog()
        p = derived_program(p, DerivedProfile.VALUE)
        phi_leaves = {
            (a.file, a.line, a.index)
            for ph in p.phis.values() for a in ph.args
            if isinstance(a, SSAVar)
        }
        produced_before = _ssavar_defs(p)
        live_leaves = {v for v in phi_leaves if v in produced_before}
        cleanup_unused_ssavars(p)
        produced_after = _ssavar_defs(p)
        # No phi-leaf producer may be removed.
        removed = sorted(live_leaves - produced_after)
        assert removed == [], f"cleanup removed producers of phi-leaf vars: {removed[:5]}"
