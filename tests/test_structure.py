"""Tests for the structural partition API (``tealtools.structure``).

Reuses existing sec-guide fixtures (no new DB). Skips if unavailable.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/sec_guide"


def _struct(rel: str):
    db = FIX / rel / "db"
    if not db.exists():
        pytest.skip(f"fixture DB not present: {db}")
    from tealtools.ssa import SSAProgram
    from tealtools.structure import analyze_structure
    try:
        prog = SSAProgram(str(db), verbose=False)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")
    return prog, analyze_structure(prog)


class TestPartition:
    def test_every_bb_has_exactly_one_role(self):
        prog, s = _struct("unprotected_updatable/fixed_dispatch_table")
        roles = {}
        for bb in prog.blocks.values():
            roles[bb] = s.role_of(bb)
        # routing + handlers + subroutine bodies cover all BBs, disjointly.
        sub_bbs = {bb for sub in s.subroutines for bb in sub.body}
        assert s.routing.isdisjoint(s.handlers)
        assert s.routing.isdisjoint(sub_bbs)
        assert s.handlers.isdisjoint(sub_bbs)
        assert len(s.routing) + len(s.handlers) + len(sub_bbs) == len(prog.blocks)

    def test_dispatch_is_subset_of_routing(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        assert s.dispatch <= s.routing
        # This fixture dispatches on OnCompletion, so dispatch is non-empty.
        assert s.dispatch


class TestSubroutinesAndCalls:
    def test_dispatch_table_subroutines_and_callers(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        names = {sub.name for sub in s.subroutines}
        assert "require_creator" in names
        # require_creator is called from two sites; both are captured.
        rc = next(sub for sub in s.subroutines if sub.name == "require_creator")
        assert len(rc.callers) >= 2
        # Every call site resolves to a known subroutine entry + name.
        for c in s.call_sites:
            assert c.target_entry is not None
            assert c.target_name in names

    def test_linear_call_chain_has_no_routing(self):
        # A main flow that's a straight callsub chain (no OnCompletion
        # dispatch) has an empty routing region; the validators are subs.
        _, s = _struct("tx_type_check/fixed_subroutine_dispatch")
        assert s.routing == frozenset()
        assert {sub.name for sub in s.subroutines} >= {
            "validate_type", "validate_amount", "validate_receiver",
        }
        assert len(s.call_sites) >= 3


class TestSlice:
    def test_assignments_in_routing_are_dispatch_only(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        ops = {a.op for a in s.assignments_in(s.routing)}
        # Routing must not contain side-effecting work.
        assert ops.isdisjoint({
            "itxn_submit", "app_global_put", "app_local_put", "log",
        })
