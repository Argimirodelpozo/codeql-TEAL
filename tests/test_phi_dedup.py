"""Tests for phi de-duplication (``tealtools.passes.phi_dedup``).

Exercised on xgov, whose constant-stack unroll over-generates phis
(~21k objects, ~667 distinct). Skips if the fixture DB isn't available.
"""
from pathlib import Path

import pytest

XGOV = Path(__file__).resolve().parent / "dbs/xgov-db"


def _prog():
    if not XGOV.exists():
        pytest.skip("xgov-db fixture not present")
    from tealtools.ssa import SSAProgram
    try:
        return SSAProgram(str(XGOV), verbose=False)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")


class TestDedup:
    def test_reduces_phi_count(self):
        p = _prog()
        before = len(p.phis)
        removed = p.dedup_phis()
        after = len(p.phis)
        assert removed == before - after
        # xgov over-generates massively; expect an order-of-magnitude cut.
        assert after < before // 10

    def test_no_surviving_duplicates(self):
        from tealtools.passes.phi_dedup import _phi_sig
        p = _prog()
        p.dedup_phis()
        seen = set()
        for ph in p.phis.values():
            s = _phi_sig(ph)
            assert s not in seen, "two survivors share a (bb, kind, args) signature"
            seen.add(s)

    def test_no_dangling_phi_args(self):
        from tealtools.ssa import Phi
        p = _prog()
        p.dedup_phis()
        survivors = set(p.phis.values())
        for ph in p.phis.values():
            for arg in ph.args:
                if isinstance(arg, Phi):
                    assert arg in survivors, "phi arg references a removed duplicate"

    def test_idempotent(self):
        p = _prog()
        p.dedup_phis()
        assert p.dedup_phis() == 0

    def test_bounds_materialization(self):
        # The point of running it before materialize: far fewer mat_phis.
        def matphis(dedup):
            q = _prog()
            q.propagate_constants()
            q.propagate_inputs()
            q.propagate_stack_shuffles()
            q.cleanup_unused_ssavars()
            q.eliminate_dead_constants()
            if dedup:
                q.dedup_phis()
            q.materialize_phis()
            return len(q.mat_phis)

        without = matphis(False)
        with_ = matphis(True)
        assert with_ < without // 10, (without, with_)
