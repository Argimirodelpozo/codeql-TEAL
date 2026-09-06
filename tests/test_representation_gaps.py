"""Historical gaps stay fixed at their exact source sites and routine contexts."""
from pathlib import Path
import json

import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.relations import unresolved_call_results


def program(body):
    return SSAProgram.from_text('#pragma version 8\n' + body, name='joins.teal')


@pytest.mark.parametrize('terminal', ['return', 'err'])
def test_a_whole_program_halt_has_no_subroutine_return_obligation(terminal):
    p = program('callsub halt\npop\nint 1\nreturn\nhalt:\nproto 0 1\nint 1\n' + terminal)
    assert not unresolved_call_results(p)


@pytest.mark.parametrize('proto', ['proto 0 1\n', ''])
def test_call_returns_and_direct_branch_values_all_reach_the_join(proto):
    p = program('txn NumAppArgs\nbnz direct\ncallsub choose\njoin:\nitob\nlog\nint 1\nreturn\n'
                'direct:\nint 7\nb join\nchoose:\n' + proto +
                'txn Fee\nbnz nonzero\nint 1\nretsub\nnonzero:\nint 2\nretsub')
    value = next(a.inputs[0] for a in p.assignments if a.op == 'itob')
    facts = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
    assert facts.constant(value) is None
    actual = facts.int_range(value)
    # Independent concrete cases: the direct path logs 7, while the call logs
    # either 1 or 2. The old merge folded every path to the direct-path 7.
    assert (actual.lo, actual.hi) == (1, 7)
    assert {a.const_value.value for a in value.args} == {'1', '2', '7'}
    assert not unresolved_call_results(p)


def test_a_recursive_return_can_share_its_continuation_with_a_branch():
    p = program('int 2\ncallsub count\nitob\nlog\nint 1\nreturn\ncount:\nproto 1 1\n'
                'frame_dig -1\nbz zero\nframe_dig -1\nint 1\n-\ndup\nbz direct\n'
                'callsub count\njoin:\nint 1\n+\nretsub\ndirect:\npop\nint 0\nb join\n'
                'zero:\nint 0\nretsub')
    assert not unresolved_call_results(p)
    join = next(a for a in p.assignments if a.op == '+')
    assert len(join.inputs) == 2
    # A recursive input stays in the value graph; it cannot be replaced by the
    # direct arm's zero (which would make count(2) return one).
    facts = p.facts(FactDomain.CONSTANTS)
    assert facts.constant(join.inputs[1]) is None


ROOT = Path(__file__).parent
GAPS = json.loads((ROOT / 'representation_gaps.json').read_text())


@pytest.mark.parametrize('name', ['app_3350348253', 'app_2450526014', 'app_3550180073',
                                'app_1850858495', 'app_1850904282'])
def test_all_seven_historical_corpus_return_gaps_are_resolved(name):
    assert not unresolved_call_results(SSAProgram(str(ROOT / 'mainnet-random-probes' / (name + '.teal'))))


@pytest.mark.parametrize('name,expected', GAPS.items())
def test_historical_gaps_are_resolved_at_their_exact_locations(name, expected):
    from tests.corpus_manifest import _ARITY_SKIP
    from tealql.tealtools.cfg.subroutines import identify_subroutines
    from tealql.tealtools.language.avm import op_arity
    from tealql.tealtools.ssa.relations import shared_execution_blocks, unresolved_shared_execution_blocks
    p = SSAProgram(str(ROOT / 'mainnet-random-probes' / (name + '.teal')))
    missing = {str(a.location.line): a for a in p.assignments if a.op not in _ARITY_SKIP
               and len(a.inputs) < max(0, op_arity(a.op, a.immediates)[0])}
    assert not missing
    assert not unresolved_shared_execution_blocks(p)
    shared = shared_execution_blocks(p)
    assert {str(b.key[1]): b.key[2] for b in shared} == {
        line: row[0] for line, row in expected.get('shared', {}).items()}
    info, py = identify_subroutines(p), p._pyssa
    for line, cause in expected.get('resolved', {}).items():
        assignment = next(a for a in p.assignments if a.location.line == int(line))
        assert len(assignment.inputs) == op_arity(assignment.op, assignment.immediates)[0]
        if cause == 'guarded-return':
            # The preceding helper returns one cell on failure and two on
            # success. Its flag guard now retains the surviving return shape.
            call = next(a for a in p.assignments if a.location.line == int(line) - 2)
            entry = info['callsub_target'][call.basic_block]
            assert assignment.op == 'store' and call.op == 'callsub'
            assert (entry.file, entry.first_line, entry.last_line) in py._divergent_legacy
        else:
            assert cause == 'minimum-depth' and assignment.op == 'concat'
            caller = next(b for b, cont in info['continuations'].items() if cont is assignment.basic_block)
            entry = info['callsub_target'][caller]
            key = entry.file, entry.first_line, entry.last_line
            callee = next(b for b in py.blocks if b.key == key)
            assert callee not in py._unsafe_callee_blocks
    for block in shared:
        cause = expected['shared'][str(block.key[1])][1]
        # Does this block consume an incoming stack cell, independent of the
        # SSA operand recovery whose limitation is being classified?
        depth, needs_input = 0, False
        for op in block.ops:
            consumed, produced = op_arity(op.op, op.immediates)
            if consumed > depth:
                needs_input = True
            depth += produced - consumed
        assert needs_input is (cause == 'effect-tail')
        for entry in shared[block]:
            context = py._stack_result.contexts[entry]
            assert block in context.exit
            assert all(len(context.args[id(op)]) >= op.n_in for op in block.ops)


def test_the_census_has_no_unresolved_representation_sites():
    from tests.corpus_manifest import load_manifest
    rows = load_manifest()['representation'].values()
    assert all(row['missing'] == row['unresolved'] == row['shared_unresolved'] == 0 for row in rows)
    shared = {Path(row['path']).stem for row in rows if row['shared']}
    assert shared == {name for name, sites in GAPS.items() if sites.get('shared')}
