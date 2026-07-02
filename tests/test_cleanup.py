"""Regression tests for SSA cleanup (``tealtools.passes.cleanup``).

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
    from tealtools.ssa import SSAProgram
    try:
        return SSAProgram(str(XGOV))
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")


def _ssavar_defs(prog):
    from tealtools.ssa import SSAVar
    return {
        (o.file, o.line, o.index)
        for a in prog.assignments for o in a.outputs
        if isinstance(o, SSAVar)
    }


class TestCleanupPhiLeaf:
    def test_cleanup_keeps_phi_referenced_producers(self):
        from tealtools.ssa import SSAVar
        p = _prog()
        p.propagate_constants()
        p.propagate_stack_shuffles()
        phi_leaves = {
            (a.file, a.line, a.index)
            for ph in p.phis.values() for a in ph.args
            if isinstance(a, SSAVar)
        }
        produced_before = _ssavar_defs(p)
        live_leaves = {v for v in phi_leaves if v in produced_before}
        p.cleanup_unused_ssavars()
        produced_after = _ssavar_defs(p)
        # No phi-leaf producer may be removed.
        removed = sorted(live_leaves - produced_after)
        assert removed == [], f"cleanup removed producers of phi-leaf vars: {removed[:5]}"
