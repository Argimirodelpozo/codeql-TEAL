"""Upper-cost proofs must cover expensive alternatives and partial executions."""
import pytest

from tealql.tealtools.budget import (
    analyze_loops, analyze_opcode_budget_guards, constant_trip_cap,
    find_budget_exhaustion_candidates,
)
from tealql.tealtools.budget.upper_cost import UpperCost

from tests.loop_oracle import execute
from tests.test_loop_induction import counter_loop, program


BRANCHED = ('int 0\nloop:\ndup\nint 2\n<\nbz done\ntxn Fee\nbz step\n'
            + 'int 0\npop\n' * 12
            + 'step:\nint 1\n+\ntxn NumAppArgs\nbnz loop\n'
              'done:\npop\nint 1\nreturn\n')


def test_cheapest_cycle_and_trip_cap_cannot_suppress_expensive_paths():
    p = program(BRANCHED)
    loop = analyze_loops(p)[0]
    assert constant_trip_cap(p, loop) == 2
    cheap = execute(BRANCHED, fields={'Fee': 0, 'NumAppArgs': 1})
    expensive = execute(BRANCHED, fields={'Fee': 1, 'NumAppArgs': 1})
    assert cheap.cost < 50 < expensive.cost
    assert find_budget_exhaustion_candidates(p, guaranteed_entry_credit=50)
    upper = UpperCost(p).from_block(p.entry_blocks()[0]).upper
    assert expensive.cost <= upper
    assert find_budget_exhaustion_candidates(p, guaranteed_entry_credit=upper) == []


@pytest.mark.parametrize('threshold,expected', [(50, False), (500, True)])
def test_budget_guards_cover_bounded_loops_only_when_upper_cost_fits(threshold, expected):
    body = f'global OpcodeBudget\nint {threshold}\n>=\nassert\n' + BRANCHED
    p = program(body)
    check = analyze_opcode_budget_guards(p)[0]
    assert check.downstream_upper is not None
    assert check.sufficient is expected
    assert bool(find_budget_exhaustion_candidates(p)) is (not expected)
    for fee in (0, 1):
        run = execute(body, fields={'Fee': fee, 'NumAppArgs': 1}, credit=threshold + 1)
        if expected:
            assert run.outcome == 'approve'


NESTED = ('int 0\nstore 0\nouter:\nload 0\nint 3\n<\nbz done\n'
          'int 0\nstore 1\ninner:\nload 1\nint 4\n<\nbz inner_done\n'
          'load 1\nint 1\n+\nstore 1\nb inner\ninner_done:\n'
          'load 0\nint 1\n+\nstore 0\nb outer\ndone:\nint 1\nreturn\n')


def test_nested_loop_costs_compose_independent_trip_certificates():
    p = program(NESTED)
    assert sorted(constant_trip_cap(p, loop) for loop in analyze_loops(p)) == [3, 4]
    run = execute(NESTED)
    assert run.outcome == 'approve' and run.visits['inner'] == 15
    assert run.cost <= UpperCost(p).from_block(p.entry_blocks()[0]).upper


def test_nested_stack_counter_is_a_copy_of_the_outer_iteration():
    body = ('int 0\nouter:\ndup\nint 3\n<\nbz done\nint 0\n'
            'inner:\ndup\nint 4\n<\nbz inner_done\nint 1\n+\nb inner\n'
            'inner_done:\npop\nint 1\n+\nb outer\ndone:\npop\nint 1\nreturn\n')
    p = program(body)
    proofs = [constant_trip_cap(p, loop) for loop in analyze_loops(p)]
    assert sorted(proofs) == [3, 4]
    assert execute(body).cost <= UpperCost(p).from_block(p.entry_blocks()[0]).upper


def test_call_summaries_include_loops_and_aborting_callee_paths():
    body = ('callsub helper\nint 1\nreturn\nhelper:\ntxn Fee\nbnz abort\n'
            + counter_loop(limit=3).replace('int 1\nreturn\n', 'retsub\n')
            + 'abort:\n' + 'int 0\npop\n' * 50 + 'err\n')
    p = program(body)
    upper = UpperCost(p).from_block(p.entry_blocks()[0]).upper
    assert upper is not None
    for fee in (0, 1):
        run = execute(body, fields={'Fee': fee})
        assert run.cost <= upper
    guarded = program('global OpcodeBudget\nint 1000\n>=\nassert\n' + body)
    assert analyze_opcode_budget_guards(guarded)[0].sufficient


def test_unbounded_aborting_callee_branch_prevents_an_upper_proof():
    p = program('callsub helper\nint 1\nreturn\nhelper:\ntxn Fee\nbz done\n'
                'forever:\nb forever\ndone:\nretsub\n')
    assert UpperCost(p).from_block(p.entry_blocks()[0]).upper is None


def test_recursive_call_cost_and_query_work_exhaustion_refuse():
    p = program('callsub helper\nint 1\nreturn\nhelper:\ncallsub helper\nretsub\n')
    assert UpperCost(p).from_block(p.entry_blocks()[0]).upper is None
    p = program(counter_loop())
    assert UpperCost(p, max_blocks=0).from_block(p.entry_blocks()[0]).upper is None


def test_budget_guard_inside_callee_cannot_forget_its_caller_suffix():
    p = program('callsub helper\n' + 'int 0\npop\n' * 20 + 'int 1\nreturn\n'
                'helper:\nglobal OpcodeBudget\nint 10\n>=\nassert\nretsub\n')
    check = analyze_opcode_budget_guards(p)[0]
    assert not check.sufficient and check.downstream_upper is None


def test_final_exit_check_is_charged():
    body = counter_loop(limit=2)
    p = program(body)
    run = execute(body)
    upper = UpperCost(p).from_block(p.entry_blocks()[0]).upper
    assert upper >= run.cost > 2 * analyze_loops(p)[0].iteration_cost.lower
