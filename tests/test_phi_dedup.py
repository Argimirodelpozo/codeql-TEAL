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
    import os
    from tealtools.ssa import SSAProgram
    # phi_dedup exists to clean up EAGER's constant-stack over-generation
    # (~21k phis on xgov). The default Braun construction emits minimal SSA
    # (~11 phis) with nothing to dedup, so build under the eager oracle to
    # exercise the pass on the over-generated set it targets.
    old = os.environ.get("TEAL_SSA_EAGER")
    os.environ["TEAL_SSA_EAGER"] = "1"
    try:
        return SSAProgram(str(XGOV), verbose=False)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")
    finally:
        if old is None:
            os.environ.pop("TEAL_SSA_EAGER", None)
        else:
            os.environ["TEAL_SSA_EAGER"] = old


class TestArgNormalization:
    def test_normalize_drops_duplicate_values_order_preserving(self):
        from tealtools.ssa import Phi, Const, SSAVar
        from tealtools.passes.phi_dedup import _normalize_args
        ph = Phi("f.teal", 1, 0, "DirectPhi")
        v = SSAVar("f.teal", 2, 1)
        c0a, c0b = Const("int", "0"), Const("int", "0")  # same value, distinct objs
        ph.args = [v, c0a, c0b, v]  # v repeated, 0 repeated (distinct const objs)
        changed = _normalize_args(ph)
        assert changed
        # First occurrence of each distinct value kept, in order.
        assert ph.args == [v, c0a]

    def test_normalize_noop_when_already_distinct(self):
        from tealtools.ssa import Phi, Const, SSAVar
        from tealtools.passes.phi_dedup import _normalize_args
        ph = Phi("f.teal", 1, 0, "DirectPhi")
        ph.args = [SSAVar("f.teal", 2, 1), Const("int", "0"), Const("int", "1")]
        before = list(ph.args)
        assert _normalize_args(ph) is False
        assert ph.args == before


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
            assert s not in seen, "two survivors share a value-normalised arg signature"
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
