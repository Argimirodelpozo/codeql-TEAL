"""Soundness gates for execution-resource analysis."""
from __future__ import annotations

import json

from tealql.tealtools.budget import (
    APP_CALL_OPCODE_BUDGET,
    LOGICSIG_MAX_COST,
    MAX_POOLED_LOGICSIG_COST,
    MAX_POOLED_OPCODE_BUDGET,
    BudgetContext,
    CostModel,
    ProgramMode,
    analyze_loops,
    block_cost,
    block_stack_delta,
    infer_avm_version,
    infer_program_mode,
    minimum_cost,
    minimum_costs,
    op_cost,
    to_dot,
)
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.analysis import DerivedProfile, derived_program


_COUNT_LOOP = (
    "#pragma version 10\nint 0\nstore 0\n"
    "loop:\nload 0\nint 5\n<\nbz done\n"
    "{body}"
    "load 0\nint 1\n+\nstore 0\nb loop\n"
    "done:\nint 1\nreturn\n"
)


def _program(source: str) -> SSAProgram:
    return SSAProgram.from_text(source, strict=False)


def _loops(source: str, *, context=None):
    return analyze_loops(_program(source), context=context)


def test_cost_facts_distinguish_exact_dynamic_and_unknown_costs():
    assert op_cost("+").lower == op_cost("+").upper == 1
    assert op_cost("sha256").lower == op_cost("sha256").upper == 35
    assert op_cost("ed25519verify").lower == 1900
    assert op_cost("ed25519verify").exact

    # Puya marks ecdsa_verify "dynamic" (its enum cannot express a per-immediate
    # cost); the AVM spec fixes it per curve, so the immediate answers EXACTLY
    # and the immediate-less query answers the true FLOOR, never 1 (2026-09-02
    # review 3.5: the dynamic early-return used to precede the table consult).
    by_curve = op_cost("ecdsa_verify", "Secp256k1")
    assert by_curve.exact and by_curve.lower == 1700
    floor = op_cost("ecdsa_verify")
    assert floor.lower == 1700 and floor.upper is None and not floor.exact
    assert "immediate-selected" in floor.reasons[0]

    unknown = op_cost("no_such_opcode_in_this_build")
    assert unknown.lower == 1 and unknown.upper is None and not unknown.exact
    assert "unknown opcode" in unknown.reasons[0]


def test_program_cost_model_resolves_immediate_and_length_dependent_costs():
    prog = _program(
        "#pragma version 10\n"
        "byte 0x00000000000000000000000000000000\n"
        "base64_decode StdEncoding\npop\n"
        "byte 0x00\ndup\ndup\ndup\ndup\n"
        "ecdsa_verify Secp256k1\npop\nint 1\nreturn\n"
    )
    model = CostModel(prog)
    base64 = next(a for a in prog.assignments if a.op == "base64_decode")
    ecdsa = next(a for a in prog.assignments if a.op == "ecdsa_verify")
    assert model.assignment_cost(base64).lower == 2  # 1 + ceil(16 / 16)
    assert model.assignment_cost(base64).exact
    assert model.assignment_cost(ecdsa).lower == 1700
    assert model.assignment_cost(ecdsa).exact


def test_program_cost_model_bounds_unknown_runtime_byte_length():
    prog = _program(
        "#pragma version 10\ntxn Note\nbase64_decode StdEncoding\npop\n"
        "int 1\nreturn\n"
    )
    fact = CostModel(prog).assignment_cost(
        next(a for a in prog.assignments if a.op == "base64_decode")
    )
    assert fact.lower >= 1
    assert fact.upper is not None
    assert not fact.exact
    assert "byte length" in fact.reasons[0]


def test_program_cost_model_selects_v1_hash_costs():
    prog = _program("#pragma version 1\nbyte 0x00\nsha256\npop\nint 1\nreturn\n")
    sha = next(a for a in prog.assignments if a.op == "sha256")
    assert CostModel(prog).assignment_cost(sha).lower == 7


def test_context_never_infers_logicsig_from_absence_of_app_only_ops():
    shared_only = _program("#pragma version 10\nint 1\nreturn\n")
    app = _program(
        '#pragma version 10\nbyte "k"\napp_global_get\npop\nint 1\nreturn\n'
    )
    assert infer_program_mode(shared_only) is ProgramMode.UNKNOWN
    assert infer_program_mode(app) is ProgramMode.APPLICATION
    assert infer_avm_version(shared_only) == 10
    assert BudgetContext.conservative(app).initial_credit == MAX_POOLED_OPCODE_BUDGET
    assert BudgetContext.conservative(shared_only).initial_credit == MAX_POOLED_LOGICSIG_COST

    lsig = BudgetContext.logic_signature()
    assert lsig.mode is ProgramMode.LOGIC_SIGNATURE
    assert lsig.initial_credit == MAX_POOLED_LOGICSIG_COST == LOGICSIG_MAX_COST * 16
    assert BudgetContext.conservative(shared_only).initial_credit == lsig.initial_credit

    one_app = BudgetContext.application(app_calls=1, inner_app_calls=0)
    assert one_app.initial_credit == APP_CALL_OPCODE_BUDGET

    clear = BudgetContext.clear_state(avm_version=10)
    assert clear.mode is ProgramMode.CLEAR_STATE
    assert clear.initial_credit == APP_CALL_OPCODE_BUDGET

    # Pooling is a protocol flag, not a program-version feature: a v4/v5
    # program in a full group (with a v6 sibling adding inner-call credit to the
    # shared pool) may obtain the whole ceiling.  Only v1-3, whose 700-unit
    # cost is enforced statically over the entire program, stay at 700.
    for version in (4, 5, 6):
        assert BudgetContext.application(
            avm_version=version, app_calls=16, inner_app_calls=256
        ).initial_credit == MAX_POOLED_OPCODE_BUDGET
    assert BudgetContext.application(
        avm_version=3, app_calls=16, inner_app_calls=256
    ).initial_credit == 700

    old_app = _program(
        '#pragma version 3\nbyte "k"\napp_global_get\npop\nint 1\nreturn\n'
    )
    assert BudgetContext.conservative(old_app).initial_credit == 700
    v4_app = _program(
        '#pragma version 4\nbyte "k"\napp_global_get\npop\nint 1\nreturn\n'
    )
    assert BudgetContext.conservative(v4_app).initial_credit == MAX_POOLED_OPCODE_BUDGET
    old_shared = _program("#pragma version 4\nint 1\nreturn\n")
    assert BudgetContext.conservative(old_shared).initial_credit == lsig.initial_credit


def test_loop_cost_uses_opcode_budget_and_explicit_context():
    context = BudgetContext.application(app_calls=1, inner_app_calls=0)
    cheap = _loops(_COUNT_LOOP.format(body=""), context=context)[0]
    pricey = _loops(
        _COUNT_LOOP.format(body="byte 0x00\nsha256\npop\n"), context=context
    )[0]
    assert cheap.iteration_cost.exact
    assert pricey.min_iteration_cost == cheap.min_iteration_cost + 35 + 2
    assert pricey.max_iterations < cheap.max_iterations
    assert cheap.budget == 700
    assert cheap.budget_bound == cheap.available_budget // cheap.min_iteration_cost


def test_cost_reads_canonical_stream_after_functional_cleanup():
    source = (
        "#pragma version 8\n"
        "loop:\n"
        "txn Fee\n"
        "txn Fee\n"
        "==\n"
        "pop\n"
        "b loop\n"
    )
    prog = _program(source)
    block = min(prog.blocks.values(), key=lambda bb: bb.first_line)
    before = block_cost(block)
    assert len(block.assignments) == len(block.stack_assignments) == 5

    view = derived_program(prog, DerivedProfile.PRESENTATION)
    view_block = min(view.blocks.values(), key=lambda bb: bb.first_line)
    assert len(view_block.assignments) < len(view_block.stack_assignments)
    assert block_cost(view_block) == before
    assert len(block.assignments) == len(block.stack_assignments)


def test_stack_delta_uses_avm_arity_when_ssa_recovery_is_partial():
    """The canonical opcode stream remains authoritative when stack simulation
    cannot attach operands.  A fully resolved spelling is the control.
    """
    unresolved = _program("#pragma version 8\n+\n")
    unresolved_block = next(iter(unresolved.blocks.values()))
    plus = next(a for a in unresolved.assignments if a.op == "+")
    assert plus.inputs == []  # pin the refusal shape, not an ordinary add
    assert block_stack_delta(unresolved_block) == -1

    resolved = _program("#pragma version 8\nint 1\nint 2\n+\n")
    resolved_block = next(iter(resolved.blocks.values()))
    assert block_stack_delta(resolved_block) == 1


def test_irreducible_two_entry_scc_is_reported():
    source = (
        "#pragma version 8\n"
        "txn Fee\n"
        "bnz a\n"
        "b b_label\n"
        "a:\n"
        "int 0\n"
        "pop\n"
        "b b_label\n"
        "b_label:\n"
        "int 0\n"
        "pop\n"
        "b a\n"
    )
    loops = _loops(source)
    assert len(loops) == 1
    assert loops[0].kind == "irreducible"
    assert len(loops[0].entries) == 2


def test_dead_cycles_are_not_reported():
    source = (
        "#pragma version 8\n"
        "b done\n"
        "dead:\n"
        "int 1\n"
        "b dead\n"
        "done:\n"
        "int 1\n"
        "return\n"
    )
    assert _loops(source) == []


def test_range_infeasible_cycles_are_not_reported():
    source = (
        "#pragma version 10\n"
        "txn OnCompletion\nint 10\n>\nbnz impossible\n"
        "int 1\nreturn\n"
        "impossible:\nb impossible\n"
    )
    assert _loops(source) == []


def test_stack_bound_requires_growth_on_every_cycle_not_the_cheapest_cycle():
    growing = _loops(
        "#pragma version 10\n"
        "loop:\nint 1\ntxn NumAppArgs\nbnz loop\n"
        "int 1\nreturn\n"
    )[0]
    assert growing.stack_growth == 1
    assert growing.stack_bound == 1000

    mixed = _loops(
        "#pragma version 10\n"
        "loop:\n"
        "txn NumAppArgs\n"
        "bnz flat\n"
        "int 1\n"
        "txn Fee\n"
        "bnz loop\n"
        "flat:\n"
        "txn Fee\n"
        "bnz loop\n"
        "int 1\n"
        "return\n"
    )[0]
    # One route grows, but the flat route can repeat forever.  Coupling stack
    # growth to whichever route happens to be cheapest would under-bound it.
    assert mixed.stack_growth is None
    assert mixed.stack_bound is None


def test_call_boundaries_disable_stack_proof_but_include_callee_cost():
    source = (
        "#pragma version 8\n"
        "loop:\n"
        "int 1\n"
        "callsub identity\n"
        "txn Fee\n"
        "bnz loop\n"
        "int 1\n"
        "return\n"
        "identity:\n"
        "proto 1 1\n"
        "frame_dig -1\n"
        "retsub\n"
    )
    loop = _loops(source)[0]
    assert loop.stack_bound is None
    assert any("call/return" in reason for reason in loop.degradations)
    assert loop.iteration_cost.exact
    # int + callsub + (proto + frame_dig + retsub) + txn + bnz
    assert loop.iteration_cost.lower == 7
    assert not any("callee execution cost" in reason for reason in loop.degradations)


def test_prefix_is_a_lower_cost_bound_and_is_subtracted():
    source = (
        "#pragma version 10\n"
        "txn NumAppArgs\nbnz expensive\n"
        "byte 0x00\nsha256\npop\nb join\n"
        "expensive:\nbyte 0x00\nkeccak256\npop\n"
        "join:\nint 0\nstore 0\n"
        "loop:\nload 0\nint 5\n<\nbz done\n"
        "load 0\nint 1\n+\nstore 0\nb loop\n"
        "done:\nint 1\nreturn\n"
    )
    loop = _loops(source)[0]
    assert 35 <= loop.prefix.lower < 130
    assert loop.available_budget == loop.budget - loop.prefix.lower
    assert loop.budget_bound == loop.available_budget // loop.iteration_cost.lower


def test_nested_reducible_loops_keep_depth():
    source = (
        "#pragma version 10\nint 0\nstore 0\n"
        "outer:\nload 0\nint 3\n<\nbz odone\nint 0\nstore 1\n"
        "inner:\nload 1\nint 4\n<\nbz idone\n"
        "load 1\nint 1\n+\nstore 1\nb inner\n"
        "idone:\nload 0\nint 1\n+\nstore 0\nb outer\n"
        "odone:\nint 1\nreturn\n"
    )
    outer, inner = _loops(source)
    assert inner.body < outer.body
    assert (outer.depth, inner.depth) == (0, 1)


def test_minimum_cost_can_prove_a_target_budget_infeasible():
    prog = _program(
        "#pragma version 10\nbyte 0x00\nsha256\nsha256\npop\nint 1\nreturn\n"
    )
    target = next(a for a in prog.assignments if a.op == "return")
    tiny = BudgetContext(ProgramMode.APPLICATION, 10, 10)
    result = minimum_cost(prog, target, context=tiny)
    assert result.cost is not None and result.cost.lower >= 70
    assert result.proven_over_budget
    assert result.verdict == "budget-infeasible"


def test_minimum_cost_prunes_range_infeasible_shortcut():
    prog = _program(
        "#pragma version 10\n"
        "txn OnCompletion\nint 10\n>\nbnz cheap\n"
        "byte 0x00\nsha256\nsha256\npop\nb join\n"
        "cheap:\nb join\n"
        "join:\nint 1\nreturn\n"
    )
    target = next(a for a in prog.assignments if a.op == "return")
    result = minimum_cost(prog, target)
    assert result.cost is not None
    assert result.cost.lower >= 70
    assert not any(block.first_line == 11 for block in result.path)


def test_minimum_cost_charges_returning_callee_once():
    prog = _program(
        "#pragma version 10\n"
        "int 1\ncallsub hash\nint 1\nreturn\n"
        "hash:\nproto 1 0\nbyte 0x00\nsha256\npop\nretsub\n"
    )
    target = next(a for a in prog.assignments if a.op == "return")
    model = CostModel(prog)
    info = model._subroutine_info()
    caller = next(iter(info["callsub_target"]))
    callee = info["callsub_target"][caller]
    continuation = info["continuations"][caller]
    expected = (
        model.block_cost(caller)
        + model.subroutine_cost(callee)
        + model.block_cost(continuation)
    )
    result = minimum_cost(prog, target)
    assert result.cost is not None
    assert result.cost == expected


def test_minimum_cost_keeps_separate_lower_and_finite_upper_witnesses():
    prog = _program(
        "#pragma version 10\n"
        "txn Fee\nbnz dynamic\n"
        "byte 0x00\nsha256\npop\nb join\n"
        "dynamic:\ntxn Note\nbase64_decode StdEncoding\npop\n"
        "join:\nint 1\nreturn\n"
    )
    target = next(a for a in prog.assignments if a.op == "return")
    context = BudgetContext(ProgramMode.APPLICATION, 10, 50)
    result = minimum_cost(prog, target, context=context)
    assert result.cost is not None and result.cost.upper is not None
    assert result.cost.upper > context.initial_credit
    assert result.within_budget_cost is not None
    assert result.within_budget_cost.upper <= context.initial_credit
    assert result.has_within_budget_path
    assert result.path != result.within_budget_path


def test_minimum_costs_shares_two_shortest_path_searches(monkeypatch):
    import tealql.tealtools.budget.queries as queries

    prog = _program(
        "#pragma version 10\ntxn Fee\nbnz yes\nint 0\nreturn\n"
        "yes:\nint 1\nreturn\n"
    )
    calls = 0
    original = queries.nx.single_source_dijkstra

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(queries.nx, "single_source_dijkstra", counted)
    results = minimum_costs(prog)
    assert len(results) == len(prog.blocks)
    assert calls == 2  # lower witness + finite-upper witness, not 2 * blocks


def test_dot_marks_loop_regions_and_cost_precision():
    dot = to_dot(_program(_COUNT_LOOP.format(body="")))
    assert dot.startswith("digraph loop_bounds {")
    assert "subgraph cluster_0" in dot
    assert "reducible" in dot
    assert "/iter (exact)" in dot
    assert "cycle" in dot


def test_loops_cli_exposes_explicit_budget_context(tmp_path, capsys):
    from tealql.cli.main import main

    source = tmp_path / "loop.teal"
    source.write_text("#pragma version 10\nloop:\ntxn Fee\nbnz loop\nint 1\nreturn\n")
    assert main([
        "loops", str(source), "--json", "--budget-mode", "clear-state"
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["context"]["mode"] == "clear-state"
    assert payload["context"]["initial_credit"] == 700
    assert payload["loops"][0]["kind"] == "reducible"
    assert "degradations" in payload["loops"][0]

    assert main([
        "loops", str(source), "--budget-mode", "clear-state", "--app-calls", "2"
    ]) == 2
    assert "does not accept pooled" in capsys.readouterr().err


def test_pragma_less_source_is_version_1():
    """The assembler defaults to version 1 when no `#pragma version` is
    present, so a readable pragma-less source must report 1 — otherwise the v1
    hash-cost override never fires and `sha256` prices as 35-EXACT where the
    real v1 cost is 7 (an over-stated lower bound, the unsound direction for
    over-budget proofs)."""
    prog = _program("byte 0x00\nsha256\npop\nint 1\nreturn\n")
    assert infer_avm_version(prog) == 1
    sha = next(a for a in prog.assignments if a.op == "sha256")
    assert CostModel(prog).assignment_cost(sha).lower == 7


def test_in_callee_target_is_not_double_charged():
    """`_path_cost` charged the full callee summary on every prefix block, so
    a witness path entering the callee through the raw callsub edge counted
    the callee TWICE — and `proven_over_budget` (a documented can't-happen)
    fired at a truly affordable in-callee target."""
    teal = ("#pragma version 8\n"
            "callsub big\nint 1\nreturn\n"
            "big:\nproto 0 0\n"
            + "byte 0x01\nsha256\npop\n" * 5
            + "retsub\n")
    prog = _program(teal)
    target = next(a for a in prog.assignments if a.op == "retsub")
    result = minimum_cost(prog, target)
    # 5×(1+35+1) in the callee + the cheap caller prefix: nowhere near double.
    assert result.cost.lower < 200, f"callee double-charged: {result.cost}"
    exact = BudgetContext(result.context.mode, result.context.avm_version,
                          result.cost.lower, provenance="test")
    at_minimum = minimum_cost(prog, target, context=exact)
    assert not at_minimum.proven_over_budget, (
        "wrong budget-infeasible PROOF at the exact minimum credit")
