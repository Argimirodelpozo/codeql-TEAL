"""Independent integer oracles for interval/residue and numeric call facts."""
from functools import reduce
from itertools import product

import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.analysis.congruences import Congruence, CongruenceQuery, binary
from tealql.tealtools.ssa import IntRange, SSAProgram


def _program(body):
    program = SSAProgram.from_text('#pragma version 8\n' + body)
    return program, program.facts(FactDomain.RANGES)


def _contains(residue, value):
    return (value == residue.residue if residue.modulus == 0
            else (value - residue.residue) % residue.modulus == 0)


@pytest.mark.parametrize('op', ['+', '-', '*', '/', '%', '&', '|', '^', 'shl', 'shr'])
def test_congruence_transfers_contain_independent_integer_results(op):
    samples = [[0], [1], [2], [7], [0, 4, 8], [1, 5, 9], [6, 12, 18], [63, 64, 65],
               [2**63, 2**63 + 4], [2**64 - 1]]
    mask = 2**64 - 1
    for left, right in product(samples, repeat=2):
        a, b = [reduce(Congruence.join, (Congruence(0, n) for n in values)) for values in (left, right)]
        abstract = binary(op, a, b)
        for x, y in product(left, right):
            if op in {'/', '%'} and y == 0 or op in {'shl', 'shr'} and y >= 64:
                continue
            if op == '+':
                result = x + y
            elif op == '-':
                result = x - y
            elif op == '*':
                result = x * y
            elif op == '/':
                result = x // y
            elif op == '%':
                result = x % y
            elif op == '&':
                result = x & y
            elif op == '|':
                result = x | y
            elif op == '^':
                result = x ^ y
            elif op == 'shl':
                result = (x << y) & mask
            else:
                result = x >> y
            if 0 <= result <= mask:
                assert _contains(abstract, result), (op, left, right, abstract, result)


def test_inductive_loop_stride_and_exit_bounds_against_execution():
    for start, step, limit in product(range(3), range(1, 6), (1, 2, 9, 10, 17)):
        program, facts = _program(f'int {start}\nloop:\ndup\nint {limit}\n<\nbz end\nint {step}\n+\nb loop\nend:\nreturn\n')
        end = next(a for a in program.assignments if a.op == 'return')
        result = start
        while result < limit:
            result += step
        bounds = facts.range_at(end.inputs[0], end)
        assert bounds is not None and bounds.lo <= result <= bounds.hi
        residue = facts.congruence(end.inputs[0])
        assert _contains(residue, result)
        if start == 0 and step == 4 and limit == 10:
            assert bounds == IntRange(12, 12) and residue == Congruence(4, 0)


def test_loop_reset_joins_every_residue_and_query_order():
    body = '''int 0
loop:
dup
int 50
<
bz end
txn NumAppArgs
bz step
pop
int 3
b loop
step:
int 4
+
b loop
end:
return
'''
    for reverse in (False, True):
        program, facts = _program(body)
        uses = [a for a in program.assignments if a.op in {'+', 'return'}]
        if reverse:
            uses.reverse()
        results = {a.op: facts.range_at(a.inputs[-1], a) for a in uses}
        end = results['return']
        assert end is not None and end.lo <= 51 <= 52 <= end.hi
        returned = next(a for a in uses if a.op == 'return').inputs[0]
        assert facts.congruence(returned) == Congruence()


def test_bounds_close_transitive_and_difference_relations():
    program, facts = _program('txn Fee\ntxn LastValid\n<\nassert\n'
                              'txn LastValid\nint 100\n<\nassert\ntxn Fee\nreturn\n')
    end = next(a for a in program.assignments if a.op == 'return')
    assert facts.range_at(end.inputs[0], end) == IntRange(0, 98)
    program, facts = _program('txn LastValid\ntxn FirstValid\n-\nint 10\n<=\nassert\n'
                              'txn FirstValid\nint 100\n<\nassert\ntxn LastValid\nreturn\n')
    end = next(a for a in program.assignments if a.op == 'return')
    assert facts.range_at(end.inputs[0], end).hi == 109


def test_mask_divisibility_and_interval_reduction_prove_exact_floor_division():
    from tealql.security.obligations import ObligationContext, conservation_obligation
    program, facts = _program('txn Fee\nint 255\n&\nint 4\n*\nint 4\n/\nreturn\n')
    division = next(a for a in program.assignments if a.op == '/')
    assert facts.congruence(division.inputs[1]).divisible_by(4)
    assert facts.range_at(division.outputs[0], division) == IntRange(0, 255)
    result = conservation_obligation(ObligationContext(program),
        {'line': division.location.line, 'left': 0, 'right': 0, 'unit': 'fixture-count'})
    assert next(r for r in result if r.kind == 'rounding').status == 'PROVED'
    assert binary('&', Congruence(), Congruence(0, 0xFC)).divisible_by(4)


@pytest.mark.parametrize('budget,steps', [(0, 4096), (128, 0), (2, 4096)])
def test_numeric_exhaustion_never_publishes_a_partial_fixpoint(budget, steps):
    program, facts = _program('txn Fee\nint 4\n*\nreturn\n')
    value = next(a for a in program.assignments if a.op == 'return').inputs[0]
    query = CongruenceQuery(facts, budget=budget, steps=steps)
    assert query.query(value) == Congruence() and query.exhausted
    assert not query.cache


def test_numeric_call_instances_do_not_merge_and_composition_preserves_order():
    program, facts = _program('txn Fee\nint 10\n<\nassert\ntxn Fee\ncallsub twice\nstore 0\n'
                              'int 7\ncallsub twice\nreturn\ntwice:\nproto 1 1\nframe_dig -1\nint 2\n*\nretsub\n')
    first, second = [a for a in program.assignments if a.op == 'callsub']
    assert facts.call_result(second).bounds == IntRange(14, 14)
    assert facts.call_result(first).bounds == IntRange(0, 18)
    assert facts.call_result(first).congruence.divisible_by(2)
    assert facts.call_result(second).bounds == IntRange(14, 14)
    assert program.revision == 0
    program.propagate_constants()
    with pytest.raises(RuntimeError, match='stale facts'):
        facts.call_result(first)

    program, facts = _program('int 5\ncallsub outer\nreturn\nouter:\nproto 1 1\n'
                              'frame_dig -1\ncallsub twice\nint 1\n+\nretsub\n'
                              'twice:\nproto 1 1\nframe_dig -1\nint 2\n*\nretsub\n')
    call = next(a for a in program.assignments if a.op == 'callsub')
    assert facts.call_result(call).bounds == IntRange(11, 11)

    program, facts = _program('int 9\nint 4\ncallsub pair\n+\nreturn\npair:\nproto 2 2\n'
                              'frame_dig -2\nframe_dig -1\n-\nframe_dig -2\nint 2\n*\nretsub\n')
    call = next(a for a in program.assignments if a.op == 'callsub')
    assert facts.call_result(call, 0).bounds == IntRange(5, 5)
    assert facts.call_result(call, 1).bounds == IntRange(18, 18)


def test_frame_replacement_is_executed_in_the_summary():
    program, facts = _program('int 9\ncallsub helper\nreturn\nhelper:\nproto 1 1\n'
                              'int 4\nframe_bury -1\nframe_dig -1\nretsub\n')
    call = next(a for a in program.assignments if a.op == 'callsub')
    assert facts.call_result(call).bounds == IntRange(4, 4)


@pytest.mark.parametrize('body', [
    'frame_dig -1\nbz other\nint 1\nretsub\nother:\nint 2\nretsub',
    'frame_dig -1\ncallsub helper\nretsub',
    'frame_dig -1\nitob\nlog\nint 1\nretsub',
    'frame_dig -2\nretsub',
])
def test_unsupported_or_recursive_numeric_calls_remain_unknown(body):
    program, facts = _program('int 9\ncallsub helper\nreturn\nhelper:\nproto 1 1\n' + body)
    call = next(a for a in program.assignments if a.op == 'callsub')
    assert not facts.call_result(call).complete


def test_deep_numeric_summary_refuses_without_a_partial_answer():
    program, facts = _program('int 9\ncallsub helper\nreturn\nhelper:\nproto 1 1\n'
                              'frame_dig -1\n' + 'int 1\n+\n' * 70 + 'retsub\n')
    call = next(a for a in program.assignments if a.op == 'callsub')
    result = facts.call_result(call)
    assert result.bounds is None and not result.complete


def test_relational_expansion_is_bounded_on_a_repeated_expression_dag():
    program, facts = _program('txn Fee\n' + 'dup\n+\n' * 30 +
                              'int 100\n<=\nassert\ntxn Fee\nreturn\n')
    end = next(a for a in program.assignments if a.op == 'return')
    result = facts.range_at(end.inputs[0], end)
    # The only successful input is zero; exhausting affine expansion can lose
    # precision, but cannot discard that independently established execution.
    assert result is None or result.lo == 0
    assert facts._intervals.visits <= 128
