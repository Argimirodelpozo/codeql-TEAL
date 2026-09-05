"""Bounds must be valid at their use, including branch/loop/call boundaries."""
import pytest
from tealql.tealtools.analysis import FactDomain, DerivedProfile, derived_program
from tealql.tealtools.analysis._range_arithmetic import _arith_result_range
from tealql.tealtools.ssa import IntRange, SSAProgram


def _program(body):
    p = SSAProgram.from_text('#pragma version 8\n' + body, name='interval.teal')
    return p, p.facts(FactDomain.RANGES)


def _bounds(r):
    return (r.lo, r.hi) if r is not None else None


def test_branch_bound_flows_into_arithmetic_and_does_not_leak_to_join():
    p, facts = _program('txn Fee\ndup\nint 10\n<\nbz large\nint 1\n+\nb end\nlarge:\npop\nint 99\nend:\nreturn\n')
    add = next(a for a in p.assignments if a.op == '+')
    exit_ = next(a for a in p.assignments if a.op == 'return')
    assert _bounds(facts.range_at(add.inputs[1], add)) == (0, 9)
    assert _bounds(facts.range_at(add.outputs[0], exit_)) == (1, 10)
    final = facts.range_at(exit_.inputs[0], exit_)
    assert final is not None and final.lo <= 1 and final.hi >= 99
    for fee in range(256):
        concrete = fee + 1 if fee < 10 else 99
        assert final.lo <= concrete <= final.hi


def test_conjunction_and_loop_backedge_are_bounded():
    p, facts = _program('int 0\nloop:\ndup\nint 10\n<\nbz end\nint 1\n+\nb loop\nend:\nreturn\n')
    add = next(a for a in p.assignments if a.op == '+')
    result = facts.range_at(add.outputs[0], add)
    assert _bounds(result) == (1, 10)
    assert facts._intervals.visits <= 128
    assert all(result.lo <= i + 1 <= result.hi for i in range(10))


def test_mutually_exclusive_branch_guard_does_not_refine_other_arm():
    p, facts = _program('txn Fee\ndup\nint 10\n<\nbz large\nint 1\n+\nreturn\nlarge:\nint 2\n+\nreturn\n')
    small, large = [a for a in p.assignments if a.op == '+']
    assert _bounds(facts.range_at(small.inputs[1], small)) == (0, 9)
    assert _bounds(facts.range_at(large.inputs[1], large))[0] == 10


def test_immutable_bound_survives_subroutine_return():
    p, facts = _program('txn Fee\nint 10\n<\nassert\ncallsub helper\ntxn Fee\nint 1\n+\nreturn\nhelper:\nretsub\n')
    add = next(a for a in p.assignments if a.op == '+')
    assert _bounds(facts.range_at(add.inputs[1], add)) == (0, 9)


def test_arithmetic_has_a_type_without_operand_ranges():
    p, _ = _program('byte "counter"\napp_global_get\nint 1\n+\nreturn\n')
    view = derived_program(p, DerivedProfile.GUARDED)
    result = next(a for a in view.assignments if a.op == '+').outputs[0]
    assert result.type.kind == 'uint64'


def test_exhausted_query_budget_preserves_all_successful_values():
    from tealql.tealtools.analysis.intervals import IntervalQuery
    p, facts = _program('txn Fee\nint 1\n+\nint 1\n+\nreturn')
    exit_ = next(a for a in p.assignments if a.op == 'return')
    query = IntervalQuery(facts, budget=0)
    result = query.range_at(exit_.inputs[0], exit_)
    assert query.widenings == 1
    assert result is None or all(result.lo <= fee + 2 <= result.hi for fee in range(256))


@pytest.mark.parametrize(('op', 'left', 'right', 'expected'), [
    ('&', (8, 15), (9, 10), (8, 10)),
    ('|', (8, 15), (16, 23), (24, 31)),
    ('^', (8, 15), (8, 15), (0, 7)),
    ('%', (10, 12), (7, 7), (3, 5)),
    ('shl', (2**63, 2**63), (1, 1), (0, 0)),
    ('shr', (8, 16), (64, 70), None),
])
def test_interval_precision(op, left, right, expected):
    assert _arith_result_range(op, IntRange(*left), IntRange(*right)) == expected
