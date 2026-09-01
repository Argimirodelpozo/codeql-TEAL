"""Higher-level budget summaries, guards, and exhaustion candidates."""
from __future__ import annotations

from tealql.tealtools.budget import (
    APP_CALL_OPCODE_BUDGET,
    BudgetContext,
    analyze_loops,
    analyze_opcode_budget_guards,
    constant_trip_cap,
    find_budget_exhaustion_candidates,
    summarize_methods,
)
from tealql.tealtools.budget import advanced as budget_advanced
from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram


def _program(source: str) -> SSAProgram:
    return SSAProgram.from_text(source, strict=False)


def test_approval_group_shape_does_not_underbound_pre_guard_execution():
    prog = _program(
        "#pragma version 8\n"
        "global GroupSize\nint 2\n==\nassert\n"
        'byte "k"\napp_global_get\npop\nint 1\nreturn\n'
    )
    context = BudgetContext.tightened_application(prog)
    # GroupSize==2 is only forced on approving paths; a loop before this assert
    # could execute in a 16-member group and later reject.
    assert context.app_calls == 16
    assert context.inner_app_calls == 256
    assert context.initial_credit == (16 + 256) * APP_CALL_OPCODE_BUDGET


def test_opcode_budget_guard_proves_only_finite_acyclic_cover():
    sufficient = _program(
        "#pragma version 8\n"
        "global OpcodeBudget\nint 10\n>=\nassert\n"
        "int 1\nreturn\n"
    )
    checks = analyze_opcode_budget_guards(sufficient)
    assert len(checks) == 1
    assert checks[0].sufficient
    assert checks[0].downstream_upper <= checks[0].guaranteed_credit

    weak = _program(
        "#pragma version 8\n"
        "global OpcodeBudget\nint 2\n>=\nassert\n"
        "int 1\nreturn\n"
    )
    check = analyze_opcode_budget_guards(weak)[0]
    assert check.verdict == "insufficient-guarantee"
    assert not check.sufficient


def test_loop_after_budget_guard_refuses_a_finite_upper_proof():
    prog = _program(
        "#pragma version 8\n"
        "global OpcodeBudget\nint 10\n>=\nassert\n"
        "loop:\ntxn Fee\nbnz loop\nint 1\nreturn\n"
    )
    check = analyze_opcode_budget_guards(prog)[0]
    assert check.downstream_upper is None
    assert check.verdict != "sufficient"
    assert any("cycle" in reason for reason in check.reasons)


def test_method_summary_carries_minimum_exit_cost_and_loop_regions():
    prog = _program(
        "#pragma version 8\n"
        "txn NumAppArgs\nbz reject\n"
        "byte 0x00\nsha256\npop\nint 1\nreturn\n"
        "reject:\nint 0\nreturn\n"
    )
    summaries = summarize_methods(prog)
    assert summaries
    assert any(summary.minimum_required is not None for summary in summaries)
    assert any(summary.approving_exits for summary in summaries)
    assert all(summary.context.initial_credit > 0 for summary in summaries)


def test_method_minimum_ignores_cheaper_rejection_exits():
    prog = _program(
        "#pragma version 8\n"
        "txn NumAppArgs\nbnz approve\nint 0\nreturn\n"
        "approve:\nbyte 0x00\nsha256\npop\nint 1\nreturn\n"
    )
    summary = next(s for s in summarize_methods(prog) if s.approving_exits)
    assert summary.minimum_required is not None
    assert summary.minimum_required.lower >= 35


def test_attacker_controlled_budget_loop_is_a_review_candidate():
    prog = _program(
        "#pragma version 8\nloop:\ntxn Fee\nbnz loop\nint 1\nreturn\n"
    )
    candidates = find_budget_exhaustion_candidates(prog)
    assert len(candidates) == 1
    assert candidates[0].attacker_controlled
    assert "ranking function" in candidates[0].reason


def test_counting_loop_with_a_constant_cap_is_not_a_candidate():
    """``for (i = 0; i < 24; i += 1)`` already HAS the explicit iteration cap the finding asks a
    reviewer to establish, so reporting it asks for something the code carries.

    The attacker decides whether to take each back edge, but the monotone counter independently
    limits that decision to 24 laps. TEALScript compiles every fixed-size StaticArray walk into this
    shape, so the pattern is ubiquitous.
    """
    prog = _program(
        "#pragma version 8\n"
        "int 0\n"
        "loop:\ndup\nint 24\n<\nbz done\n"
        "byte 0x00\nsha256\npop\n"
        "int 1\n+\n"
        "txn NumAppArgs\nbnz loop\n"          # attacker-influenced back edge
        "done:\npop\nint 1\nreturn\n"
    )
    assert find_budget_exhaustion_candidates(prog) == []


def test_constant_comparison_does_not_hide_an_unchanged_counter():
    """A constant comparison is not a cap when the back edge makes no progress."""
    prog = _program(
        "#pragma version 8\n"
        "int 0\n"
        "loop:\ndup\nint 24\n<\nbz done\n"
        "byte 0x00\nsha256\npop\n"
        "txn NumAppArgs\nbnz loop\n"
        "done:\npop\nint 1\nreturn\n"
    )
    assert len(find_budget_exhaustion_candidates(prog)) == 1


def test_constant_comparison_respects_exit_edge_polarity():
    """``bnz done`` continues when ``counter < bound`` is false, not true."""
    prog = _program(
        "#pragma version 8\n"
        "int 24\n"
        "loop:\ndup\nint 24\n<\nbnz done\n"
        "byte 0x00\nsha256\npop\n"
        "int 1\n+\ntxn NumAppArgs\nbnz loop\n"
        "done:\npop\nint 1\nreturn\n"
    )
    assert len(find_budget_exhaustion_candidates(prog)) == 1


def test_constant_guard_on_a_bypassable_path_does_not_cap_the_loop():
    """A body-local guard cannot bound laps that take another back-edge path."""
    prog = _program(
        "#pragma version 8\n"
        "int 0\n"
        "loop:\ntxn NumAppArgs\nbnz loop\n"  # attacker can bypass the guard forever
        "dup\nint 24\n<\nbz done\n"
        "int 1\n+\nb loop\n"
        "done:\npop\nint 1\nreturn\n"
    )
    assert len(find_budget_exhaustion_candidates(prog)) == 1


def test_inclusive_constant_cap_counts_the_boundary_iteration():
    prog = _program(
        "#pragma version 8\n"
        "int 0\n"
        "loop:\ndup\nint 24\n<=\nbz done\n"
        "int 1\n+\ntxn NumAppArgs\nbnz loop\n"
        "done:\npop\nint 1\nreturn\n"
    )
    loop = analyze_loops(prog)[0]
    facts = prog.facts(FactDomain.CONSTANTS)
    assert budget_advanced._constant_trip_cap(prog, loop, facts) == 25
    assert constant_trip_cap(prog, loop) == 25


def test_descending_constant_cap_proves_progress_in_the_other_direction():
    prog = _program(
        "#pragma version 8\n"
        "int 24\n"
        "loop:\ndup\nint 0\n>\nbz done\n"
        "int 1\n-\ntxn NumAppArgs\nbnz loop\n"
        "done:\npop\nint 1\nreturn\n"
    )
    loop = analyze_loops(prog)[0]
    facts = prog.facts(FactDomain.CONSTANTS)
    assert budget_advanced._constant_trip_cap(prog, loop, facts) == 24
    assert find_budget_exhaustion_candidates(prog) == []


def test_loop_bounded_by_a_non_constant_is_still_a_candidate():
    """The cap must be a CONSTANT. A limit read from state or arguments bounds nothing on its own,
    so those keep being reported."""
    prog = _program(
        "#pragma version 8\n"
        "int 0\nstore 0\n"
        "loop:\n"
        "load 0\ntxn NumAppArgs\n<\nbz done\n"   # limit is attacker-supplied
        "load 0\nint 1\n+\nstore 0\nb loop\n"
        "done:\nint 1\nreturn\n"
    )
    assert len(find_budget_exhaustion_candidates(prog)) == 1


def test_header_controlled_while_loop_is_a_review_candidate():
    """The continuation condition usually lives at the header while the back
    edge is an unconditional ``b``.  The condition still controls whether the
    loop gets another lap."""
    prog = _program(
        "#pragma version 8\n"
        "loop:\ntxn NumAppArgs\nbz done\n"
        "byte 0x00\nsha256\npop\nb loop\n"
        "done:\nint 1\nreturn\n"
    )
    candidates = find_budget_exhaustion_candidates(prog)
    assert len(candidates) == 1
    assert candidates[0].loop.header.first_line == 2


def test_nested_cycle_voids_an_outer_stack_ceiling_and_counts_toward_cap(monkeypatch):
    """Two inner -1 laps offset the outer +2 pushes, so the outer loop can
    remain stack-flat.  Non-header cycles must also consume the enumeration
    budget even when they are positive and do not otherwise void the proof.
    """
    import tealql.tealtools.budget.loop_bounds as loop_bounds
    from tealql.tealtools.cfg import CFG

    prog = _program(
        "#pragma version 10\n"
        "outer:\nint 1\nint 1\nint 2\nstore 0\n"
        "inner:\npop\nload 0\nint 1\n-\ndup\nstore 0\nbnz inner\n"
        "txn Fee\nbnz outer\nint 1\nreturn\n"
    )
    loops = analyze_loops(prog)
    outer = next(loop for loop in loops if loop.depth == 0)
    assert outer.stack_growth is None
    assert outer.stack_bound is None
    assert any(candidate.loop.header is outer.header
               for candidate in find_budget_exhaustion_candidates(prog))

    graph, roots = loop_bounds._routine_graph(prog, CFG.of(prog))
    outer_shape = max(loop_bounds._loop_shapes(graph, roots), key=lambda s: len(s.body))
    inner_node = next(node for node in outer_shape.body if node.first_line == 7)
    monkeypatch.setattr(loop_bounds, "block_stack_delta", lambda _bb: 1)
    monkeypatch.setattr(
        loop_bounds.nx, "simple_cycles",
        lambda _graph: iter(([inner_node], [outer_shape.header])),
    )
    growth, reason = loop_bounds._guaranteed_stack_growth(
        outer_shape, graph, max_cycles=1,
    )
    assert growth is None
    assert reason == "stack proof exceeded 1 simple cycles"


def test_expensive_growing_loop_can_exhaust_budget_before_stack():
    # Expensive enough to exhaust even the 320k unknown-mode ceiling before
    # 1000 stack-growing laps.
    expensive = "".join("byte 0x00\nsha256\npop\n" for _ in range(9))
    prog = _program(
        "#pragma version 10\nloop:\nint 1\n"
        + expensive
        + "txn Fee\nbnz loop\nint 1\nreturn\n"
    )
    loop = find_budget_exhaustion_candidates(prog)[0].loop
    assert loop.stack_bound is not None
    assert loop.budget_bound < loop.stack_bound


def test_constant_capped_loops_are_dropped_on_a_real_contract():
    """The synthetic cap fixtures above pass with OR without ``_constant_trip_cap``
    (verified by running them against the pre-fix sources), so they pin nothing on
    their own: the hand-written shapes never reach the loop-carried-Phi test the
    helper requires.

    Reti's ValidatorRegistry is the shape the fix was measured on, and it does
    exercise it — ten candidates before, five after, the dropped five capped at 3
    to 24 by StaticArray capacities against reported bounds in the thousands. The
    five that REMAIN are bounded by state values (``curNumPools``,
    ``maxPoolsPerNodeForThisValidator``), which bound nothing on their own, so this
    pins both directions at once: the cap drops what it should and keeps what it
    must."""
    from pathlib import Path

    contract = (Path(__file__).resolve().parent
                / "contracts" / "reti-crossfamily-phi" / "approval.teal")
    if not contract.exists():
        import pytest
        pytest.skip("reti fixture not present")
    prog = SSAProgram(str(contract), strict=False)
    candidates = find_budget_exhaustion_candidates(prog)
    assert len(candidates) == 5, (
        f"budget-exhaustion candidates moved to {len(candidates)} (expected 5). "
        f"Ten before the constant-cap fix; a rise back toward ten means the cap "
        f"stopped being credited, a fall means a state-bounded loop was dropped.")


def test_opaque_leaf_conditions_are_attacker_possible():
    """The attacker-rooted walk DIED at no-input opaque reads — a group
    sibling's scratch (`gloads`, attacker-assembled group) or an unresolved
    multi-store `load` — and returned False, silently excluding exactly the
    loops a reviewer must see. Unknown = attacker-possible for a candidate
    generator. Control: a constant-conditioned loop stays excluded."""
    gloads_loop = _program(
        "#pragma version 8\nloop:\nint 0\ngloads 0\nbz done\nb loop\n"
        "done:\nint 1\nreturn\n")
    assert find_budget_exhaustion_candidates(gloads_loop), (
        "group-sibling-scratch-conditioned loop must be a candidate")
    scratch_loop = _program(
        "#pragma version 8\ntxn Fee\nstore 0\ntxn Amount\nstore 0\n"
        "loop:\nload 0\nbz done\nb loop\ndone:\nint 1\nreturn\n")
    assert find_budget_exhaustion_candidates(scratch_loop), (
        "multi-store scratch-conditioned loop must be a candidate")
    const_loop = _program(
        "#pragma version 8\nint 0\nloop:\ndup\nint 24\n<\nbz done\nint 1\n+\n"
        "b loop\ndone:\nint 1\nreturn\n")
    assert not find_budget_exhaustion_candidates(const_loop), (
        "the honest bounded for-loop must stay suppressed")
