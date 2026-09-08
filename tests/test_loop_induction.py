"""Loop certificates checked against independently executed instruction traces."""
from itertools import product

import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.analysis.loop_induction import LoopAnalysis
from tealql.tealtools.budget import constant_trip_cap, analyze_loops
from tealql.tealtools.budget.upper_cost import UpperCost
from tealql.tealtools.ssa import SSAProgram, IntRange

from tests.loop_oracle import execute


def program(body):
    return SSAProgram.from_text('#pragma version 8\n' + body, name='loop.teal', strict=False)


def counter_loop(start=0, limit=10, step=1, relation='<', *, scratch=False, post=False):
    read = 'load 0\n' if scratch else 'dup\n'
    update = ('load 0\n' if scratch else '') + f'int {abs(step)}\n' + ('+\n' if step > 0 else '-\n')
    if scratch:
        update += 'store 0\n'
    init = f'int {start}\n' + ('store 0\n' if scratch else '')
    test = read + f'int {limit}\n{relation}\n'
    body = (init + 'loop:\n' + update + test + 'bnz loop\n' if post else
            init + 'loop:\n' + test + 'bz done\n' + update + 'b loop\ndone:\n')
    return body + ('load 0\n' if scratch else '') + 'itob\nlog\nint 1\nreturn\n'


@pytest.mark.parametrize('scratch,post', product((False, True), repeat=2))
@pytest.mark.parametrize('relation,step', [('<', 1), ('<=', 3), ('>', -1), ('>=', -3)])
def test_counter_certificates_cover_concrete_loops(scratch, post, relation, step):
    for start, limit in product((0, 1, 9, 10, 17), (0, 1, 10, 17)):
        body = counter_loop(start, limit, step, relation, scratch=scratch, post=post)
        p = program(body)
        facts = p.facts(FactDomain.RANGES)
        run = execute(body)
        loops = analyze_loops(p)
        if not loops:
            assert run.visits['loop'] <= 1  # the exit was proved before any backedge
            continue
        loop = loops[0]
        proof = facts.loop_analysis().summary(loop)
        if relation == '>=' and limit == 0:
            assert run.outcome == 'arithmetic'  # no normal exit exists in uint64
            continue
        assert proof.complete, proof.reason
        assert run.visits['loop'] <= proof.trip_bound + 1
        assert run.cost <= UpperCost(p).from_block(p.entry_blocks()[0]).upper
        if run.logs:
            use = next(a for a in p.assignments if a.op == 'itob')
            bounds = facts.range_at(use.inputs[0], use)
            assert bounds is not None and bounds.lo <= run.logs[0] <= bounds.hi


@pytest.mark.parametrize('scratch,post', product((False, True), repeat=2))
def test_basic_counter_caps_and_exit_values_are_precise(scratch, post):
    p = program(counter_loop(scratch=scratch, post=post))
    assert constant_trip_cap(p, analyze_loops(p)[0]) == 10
    use = next(a for a in p.assignments if a.op == 'itob')
    assert p.facts(FactDomain.RANGES).range_at(use.inputs[0], use) == IntRange(10, 10)


def test_guarded_runtime_limit_is_carried_inductively():
    body = ('txn Fee\ndup\nint 10\n<=\nassert\nint 0\nloop:\n'
            'dup\ndig 2\n<\nbz done\nint 1\n+\nb loop\ndone:\n'
            'itob\nlog\npop\nint 1\nreturn\n')
    p = program(body)
    loop = analyze_loops(p)[0]
    assert constant_trip_cap(p, loop) == 10
    use = next(a for a in p.assignments if a.op == 'itob')
    assert p.facts(FactDomain.RANGES).range_at(use.inputs[0], use) == IntRange(0, 10)
    for n in range(12):
        run = execute(body, fields={'Fee': n})
        assert run.outcome == ('approve' if n <= 10 else 'assert')
        if run.logs:
            assert run.logs == [n] and run.visits['loop'] == n + 1


def test_variable_positive_progress():
    body = counter_loop().replace('int 1\n+\n', 'txn Fee\nint 2\n%\nint 1\n+\n+\n')
    p = program(body)
    assert constant_trip_cap(p, analyze_loops(p)[0]) == 10
    for fee in range(8):
        run = execute(body, fields={'Fee': fee})
        assert run.visits['loop'] <= 11 and run.logs == [10]


@pytest.mark.parametrize('step,limit,expected', [(1, 10, 10), (2, 10, 5), (4, 10, None)])
def test_equality_exit_requires_a_reachable_residue(step, limit, expected):
    p = program(counter_loop(step=step, limit=limit, relation='!='))
    assert constant_trip_cap(p, analyze_loops(p)[0]) == expected


@pytest.mark.parametrize('update', ['int 0\n+\n', 'pop\nint 0\n', 'int 1\n-\n'])
def test_no_progress_reset_and_wrong_direction_do_not_prove_a_cap(update):
    p = program(counter_loop().replace('int 1\n+\n', update))
    assert constant_trip_cap(p, analyze_loops(p)[0]) is None


def test_dynamic_scratch_alias_refuses_the_counter():
    body = counter_loop(scratch=True).replace('b loop\n', 'txn Fee\nint 0\nstores\nb loop\n')
    p = program(body)
    proof = p.facts(FactDomain.RANGES).loop_analysis().summary(analyze_loops(p)[0])
    assert not proof.complete and 'dynamic store' in proof.reason


def test_induction_work_exhaustion_publishes_no_partial_proof():
    p = program(counter_loop())
    analysis = LoopAnalysis(p.facts(FactDomain.RANGES), budget=0)
    proof = analysis.summary(analysis.regions[0])
    assert not proof.complete and 'budget exhausted' in proof.reason


def test_uint64_failure_is_not_wrapping_progress():
    body = counter_loop(start=2**64 - 2, limit=2**64 - 1, step=2)
    run = execute(body)
    assert run.outcome == 'arithmetic' and not run.logs
    p = program(body)
    assert constant_trip_cap(p, analyze_loops(p)[0]) == 1


@pytest.mark.parametrize('branch', ['bz', 'bnz'])
def test_every_backedge_contributes_its_progress(branch):
    body = ('int 0\nloop:\ndup\nint 10\n<\nbz done\n'
            f'txn Fee\n{branch} big\nint 1\n+\nb loop\n'
            'big:\nint 4\n+\nb loop\ndone:\nitob\nlog\nint 1\nreturn\n')
    p = program(body)
    assert constant_trip_cap(p, analyze_loops(p)[0]) == 10
    use = next(a for a in p.assignments if a.op == 'itob')
    bounds = p.facts(FactDomain.RANGES).range_at(use.inputs[0], use)
    for fee in (0, 1):
        run = execute(body, fields={'Fee': fee})
        assert run.visits['loop'] <= 11
        assert bounds.lo <= run.logs[0] <= bounds.hi


def test_fixed_point_bounds_resets_without_inventing_a_trip_cap():
    body = ('int 0\nloop:\ndup\nint 50\n<\nbz done\ntxn Fee\nbz step\n'
            'pop\nint 3\nb loop\nstep:\nint 4\n+\nb loop\n'
            'done:\nitob\nlog\nint 1\nreturn\n')
    p = program(body)
    facts = p.facts(FactDomain.RANGES)
    loop = analyze_loops(p)[0]
    assert constant_trip_cap(p, loop) is None
    phi = next(phi for phi in p.phis.values() if phi.basic_block is loop.header)
    invariant = facts.loop_analysis().invariants.query(phi)
    assert invariant == IntRange(0, 53)
    assert execute(body, fields={'Fee': 1}, max_steps=500).outcome == 'step-limit'
    use = next(a for a in p.assignments if a.op == 'itob')
    result = facts.range_at(use.inputs[0], use)
    assert result is not None and result.lo <= 52 <= result.hi <= 53


@pytest.mark.parametrize('max_nodes,max_steps', [(0, 4096), (128, 0), (128, 5)])
def test_fixed_point_exhaustion_does_not_publish_seed_values(max_nodes, max_steps):
    from tealql.tealtools.analysis.loop_invariants import LoopInvariants
    p = program(counter_loop())
    analysis = p.facts(FactDomain.RANGES).loop_analysis()
    phi = next(phi for phi in p.phis.values() if phi.basic_block is analysis.regions[0].header)
    query = LoopInvariants(analysis.base, max_nodes=max_nodes, max_steps=max_steps)
    assert query.query(phi) is None and 'budget exhausted' in query.reason


def test_nested_reset_cannot_be_discarded_as_an_identity_cycle():
    from tests.test_loop_cost_upper import NESTED
    body = NESTED.replace('load 1\nint 1\n+\nstore 1\n',
                          'int 0\nstore 0\nload 1\nint 1\n+\nstore 1\n')
    p = program(body)
    outer = next(loop for loop in analyze_loops(p) if loop.depth == 0)
    assert constant_trip_cap(p, outer) is None
    assert UpperCost(p).from_block(p.entry_blocks()[0]).upper is None
    assert execute(body, max_steps=1000).outcome == 'step-limit'


def test_loop_queries_are_read_only_and_cached_by_revision():
    p = program(counter_loop())
    before = p.functional(resolve_consts=False, propagate_consts=False)
    facts = p.facts(FactDomain.RANGES)
    analysis = facts.loop_analysis()
    region = analysis.regions[0]
    assert analysis.summary(region).trip_bound == 10
    assert analysis.summary(region) is analysis.summary(region)
    assert p.functional(resolve_consts=False, propagate_consts=False) == before
    p.propagate_constants()
    with pytest.raises(RuntimeError, match='stale facts'):
        analysis.summary(region)
    assert p.facts(FactDomain.RANGES).loop_analysis() is not analysis
