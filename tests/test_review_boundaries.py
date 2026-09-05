"""Information must survive public analysis boundaries."""
from types import SimpleNamespace

import pytest

from tealql.security.findings import normalize
from tealql.tealtools.dataflow.taint_query import TaintQuery, classify_sink
from tealql.tealtools.language.avm import STATE_WRITE_OPS
from tealql.tealtools.language.effects import STATE_EFFECTS
from tealql.tealtools.lift import pre_ir as ir
from tealql.tealtools.lift.summaries import compute_summaries
from tealql.tealtools.lift.taint import user_input_taint
from tealql.tealtools.ssa import SSAProgram


@pytest.mark.parametrize('name', ['my contract.teal', 'dir/demo[2].teal',
                                  r'C:\contracts\a.teal', 'dír/x.teal'])
def test_location_round_trip(name):
    finding = normalize(SimpleNamespace(location=f'{name}:7'), rule_id='test')
    assert (finding.file, finding.line) == (name, 7)


@pytest.fixture
def collection(tmp_path):
    for name in ('a.teal', 'b.teal'):
        (tmp_path / name).write_text('#pragma version 8\ntxna ApplicationArgs 0\nlog\nint 1\nreturn\n')
    return SSAProgram(str(tmp_path))


@pytest.mark.parametrize('precise', [False, True])
def test_selected_program_is_the_only_query_program(collection, precise):
    query = TaintQuery(collection, file='b.teal')
    assert [h.location for h in query.tainted_sinks(precise=precise)] == ['b.teal:3']
    assert {n.file for n in query.all_sources()} == {'b.teal'}
    assert {h.node.file for h in TaintQuery(collection).tainted_sinks(precise=precise)} == {'a.teal', 'b.teal'}


def test_source_map_lookup_keeps_program_identity(collection):
    query = TaintQuery(collection)
    query._rev = {('source.py', 9): [('b.teal', 2)]}
    assert [h.location for h in query.sinks_from(source_file='source.py', source_line=9)] == ['b.teal:3']


def test_sink_verification_never_joins_other_file(collection, monkeypatch):
    from tealql.security import DETECTORS
    from tealql.security.sink_verdict import verify_sinks
    class Fake:
        def __init__(self, prog, **kwargs):
            pass
        def detect(self):
            return [SimpleNamespace(location='a.teal:3', field='log')]
    monkeypatch.setitem(DETECTORS, 'tainted-log', Fake)
    verdicts = {v.sink.location: v.verdict for v in verify_sinks(collection)}
    assert verdicts == {'a.teal:3': 'CONFIRMED', 'b.teal:3': 'NOT_FLAGGED'}


def test_state_effect_inventory_drives_both_consumers():
    from tealql.tealtools.lift.fund_flow import _STATE_WRITE_KEY_IDX
    assert set(STATE_EFFECTS) == STATE_WRITE_OPS == set(_STATE_WRITE_KEY_IDX)
    for op, effect in STATE_EFFECTS.items():
        assert classify_sink(op, '') == (effect.category, effect.severity)
        assert _STATE_WRITE_KEY_IDX[op] == effect.key_index


def test_division_remediation_requires_rounding_and_overflow_proofs():
    from tealql.security import DETECTORS
    maximum = 2**64 - 1
    p = SSAProgram.from_text(f'#pragma version 8\nint {maximum}\nint 2\n/\nint 2\n*\nreturn', name='arithmetic.teal')
    finding, = DETECTORS['unsafe-division-order'](p).detect()
    # Independent integer semantics: the original expression fits, but the
    # proposed product cannot execute in a uint64 AVM multiplication.
    assert (maximum // 2) * 2 <= maximum < maximum * 2
    assert (5 // 2) * 2 != (5 * 2) // 2
    message = finding.pretty().lower()
    assert 'rounding' in message and 'proving the intermediate product fits' in message
    assert 'wide arithmetic' in message and 'overflow' in message


def _positional_program(*, nested=False, recursive=False):
    parameter, input_reg, clean, tainted = [ir.Register(n, 0, 'bytes')
                                          for n in ('p', 'input', 'clean', 'tainted')]
    body = [ir.BasicBlock(1, [], [], ir.SubroutineReturn([ir.BytesConstant('0x00'), parameter]))]
    pair = ir.Subroutine('pair', [ir.Parameter(parameter)], ['bytes', 'bytes'], body)
    subs = [pair]
    target = 'pair'
    if recursive:
        a, b = ir.Register('a', 0, 'bytes'), ir.Register('b', 0, 'bytes')
        body.append(ir.BasicBlock(2, [], [ir.Assignment([a, b], ir.InvokeSubroutine('pair', [parameter]))],
                                  ir.SubroutineReturn([a, b])))
    if nested:
        q, a, b = [ir.Register(n, 0, 'bytes') for n in ('q', 'a', 'b')]
        wrapper = ir.Subroutine('wrapper', [ir.Parameter(q)], ['bytes', 'bytes'], [ir.BasicBlock(
            3, [], [ir.Assignment([a, b], ir.InvokeSubroutine('pair', [q]))], ir.SubroutineReturn([a, b]))])
        subs.append(wrapper)
        target = 'wrapper'
    main = ir.Subroutine('main', [], [], [ir.BasicBlock(0, [], [
        ir.Assignment([input_reg], ir.Intrinsic('txna', ['ApplicationArgs', '0'], [])),
        ir.Assignment([clean, tainted], ir.InvokeSubroutine(target, [input_reg]))],
        ir.ProgramExit(ir.UInt64Constant(1)))], is_main=True)
    lifter = SimpleNamespace(subs=[main, *subs], name2sub={s.id: s for s in subs},
                             register_sources={}, load_stores={})
    return lifter, clean, tainted


@pytest.mark.parametrize(('nested', 'recursive'), [(False, False), (True, False), (False, True), (True, True)])
def test_call_returns_remain_positional(nested, recursive):
    lifter, clean, tainted = _positional_program(nested=nested, recursive=recursive)
    sources = user_input_taint(lifter)
    assert not sources.get(id(clean))
    assert sources[id(tainted)] == {'ApplicationArgs'}
    pair = compute_summaries(lifter)['pair']
    assert pair.results[0].passthrough == frozenset()
    assert pair.results[1].passthrough == {0}
