"""Higher-level budget summaries, guards, and exhaustion candidates."""
from __future__ import annotations

from tealql.tealtools.budget import (
    APP_CALL_OPCODE_BUDGET,
    BudgetContext,
    analyze_loops,
    analyze_opcode_budget_guards,
    find_budget_exhaustion_candidates,
    summarize_methods,
)
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
