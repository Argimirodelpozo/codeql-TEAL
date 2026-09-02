"""Tests for the structural partition API (``tealql.tealtools.cfg.structure``).

Reuses existing sec-guide fixtures (no new fixture). Skips if unavailable.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/sec_guide"


def _struct(rel: str):
    contract = FIX / rel
    if not contract.exists():
        pytest.skip(f"fixture not present: {contract}")
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.cfg.structure import analyze_structure
    # A construction failure IS a test failure — never skip on it.
    prog = SSAProgram(str(contract))
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


class TestRender:
    def test_render_has_routing_and_subroutine_sections(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        text = s.render()
        # OnCompletion dispatch (not the ABI selector) -> "routing:".
        assert "routing:" in text
        # Each subroutine is its own labelled section with its lines.
        assert "business_logic():" in text
        assert "require_creator():" in text
        # Actual functional lines appear under sections.
        assert "txn Sender" in text
        assert "callsub business_logic" in text

    def test_handler_functions_partition_handlers(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        funcs = s.handler_functions()
        # Components are disjoint and cover exactly the handler BBs.
        covered = set()
        for _, bbs in funcs:
            assert covered.isdisjoint(bbs)
            covered |= bbs
        assert covered == set(s.handlers)
        # Labelled route targets keep their label as the function name.
        names = {name for name, _ in funcs}
        assert "handle_noop" in names

    def test_render_truncates_long_lines(self):
        _, s = _struct("unprotected_updatable/fixed_dispatch_table")
        text = s.render(max_width=40)
        # max_width caps the functional body of assignment lines (those
        # start with "    L<line>: "); section headers aren't capped.
        asg_lines = [ln for ln in text.splitlines() if ln.startswith("    L")]
        assert asg_lines  # sanity
        assert all(len(ln) <= 40 + 12 for ln in asg_lines)

    def test_arc4_router_labelled_arc4(self):
        # A real ABI contract dispatches on txna ApplicationArgs 0.
        from pathlib import Path
        contract = Path(__file__).resolve().parent / "contracts/xgov"
        if not contract.exists():
            import pytest
            pytest.skip("xgov fixture not present")
        from tealql.tealtools.ssa import SSAProgram
        from tealql.tealtools.cfg.structure import analyze_structure
        s = analyze_structure(SSAProgram(str(contract)))
        assert s.render().startswith("arc4_routing:")
