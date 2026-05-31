"""Tests for transitive execution-stable expression propagation + CSE
(``tealtools.passes.stable_prop``).

Exercised on the real xgov contract (rich in repeated stable
expressions). Skips if the fixture DB isn't available.
"""
from pathlib import Path

import pytest

XGOV = Path(__file__).resolve().parent / "dbs/xgov-db"


def _prog():
    if not XGOV.exists():
        pytest.skip("xgov-db fixture not present")
    from tealtools.ssa import SSAProgram
    try:
        p = SSAProgram(str(XGOV), verbose=False)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")
    # Match the pipeline placement: leaves unified + shuffles collapsed
    # before stable-expr CSE.
    p.propagate_constants()
    p.propagate_inputs()
    p.propagate_stack_shuffles()
    return p


class TestMarking:
    def test_derived_pure_op_of_stable_inputs_is_stable(self):
        from tealtools.passes.stable_prop import _compute_stable
        p = _prog()
        stable = _compute_stable(p)
        # The compound guard (ApplicationID != 0) && (OnCompletion == 0)
        # is a two-level pure expression over stable leaves — it must be
        # marked stable, proving stability grows transitively past depth 1.
        marked = [a for a in p.assignments
                  if a.op == "&&" and a.outputs and a.outputs[0] in stable]
        assert marked, "a pure op of stable inputs should be marked stable"

    def test_state_reads_are_not_stable(self):
        from tealtools.passes.stable_prop import _compute_stable
        p = _prog()
        stable = _compute_stable(p)
        state_outs = [
            a.outputs[0] for a in p.assignments
            if a.op in ("app_global_get", "app_local_get") and a.outputs
        ]
        assert state_outs, "xgov reads application state"
        # Mutable-within-execution reads must never be marked stable.
        assert all(o not in stable for o in state_outs)


class TestCSE:
    def test_repeated_stable_expression_unifies(self):
        from tealtools.passes.stable_prop import (
            _compute_stable, _signature, propagate_stable_expressions,
        )
        p = _prog()
        stable = _compute_stable(p)
        target = ("==", "", ("c", "int", "0"), ("leaf", "txn", "OnCompletion"))
        cache: dict = {}
        group = [v for v in stable if _signature(v, stable, cache, set()) == target]
        assert len(group) >= 2, "xgov should compute (OnCompletion == 0) at many sites"

        propagate_stable_expressions(p)
        # After CSE exactly one of the group keeps consumers; the rest are
        # rewired to it (uses cleared).
        live = [v for v in group if v.uses]
        assert len(live) == 1

    def test_idempotent(self):
        p = _prog()
        p.propagate_stable_expressions()
        assert p._stable_propagated
        # Second call is a no-op (does not raise, flag stays set).
        p.propagate_stable_expressions()
        assert p._stable_propagated
