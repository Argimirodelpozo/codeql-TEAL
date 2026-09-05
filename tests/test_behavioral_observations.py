"""The behavioral gate must observe effects and count completed comparisons."""
import pytest

from tests.behavioral_lift.observations import (
    compare_cases, observe_dryrun, required_effects,
)


def _response(value=1, *, approved=True):
    return {'txns': [{'app-call-messages': ['PASS' if approved else 'REJECT'],
                      'global-delta': [{'key': 'aw==', 'value': {'action': 2, 'uint': value}}]}]}


def test_global_changes_diverge_even_with_same_logs():
    result = compare_cases([0], lambda _: (observe_dryrun(_response(1)), observe_dryrun(_response(2))),
                           required=frozenset({'global'}))
    assert result['status'] == 'DIVERGES'
    assert result['completed'] == 1


def test_zero_completed_cases_are_inconclusive():
    def fail(_):
        raise RuntimeError('transport unavailable')
    result = compare_cases(range(10), fail, required=frozenset())
    assert result['status'] == 'INCONCLUSIVE'
    assert result['attempted'] == result['errors'] == 10
    assert result['completed'] == 0
    assert compare_cases([], fail, required=frozenset())['status'] == 'INCONCLUSIVE'


@pytest.mark.parametrize('effect', ['boxes', 'inner-transactions', 'exported-scratch'])
def test_unobserved_effect_is_inconclusive(effect):
    observation = observe_dryrun(_response())
    result = compare_cases([0], lambda _: (observation, observation), required=frozenset({effect}))
    assert result['status'] == 'INCONCLUSIVE'
    assert result['incomplete'] == 1


def test_only_rejecting_paths_are_inconclusive():
    rejected = observe_dryrun(_response(approved=False))
    assert compare_cases([0], lambda _: (rejected, rejected), required=frozenset())['status'] == 'INCONCLUSIVE'


def test_positive_complete_execution_is_a_bounded_match():
    observation = observe_dryrun(_response())
    assert compare_cases([0], lambda _: (observation, observation), required=frozenset({'global'}))['status'] == 'FAITHFUL'


def test_effect_requirements_include_both_programs():
    requirements = required_effects('#pragma version 8\nint 1\nreturn',
                                    '#pragma version 8\nbox_put\nstore 0\nitxn_submit')
    assert {'boxes', 'exported-scratch', 'inner-transactions'} <= requirements
    assert 'unsupported-semantics' in required_effects('unmodeled_instruction')


def test_delta_order_is_not_observable_but_log_order_is():
    a = _response()
    b = _response()
    extra = {'key': 'eA==', 'value': {'action': 2, 'uint': 2}}
    a['txns'][0]['global-delta'].append(extra)
    b['txns'][0]['global-delta'].insert(0, extra)
    assert observe_dryrun(a).effects == observe_dryrun(b).effects
    a['txns'][0]['logs'], b['txns'][0]['logs'] = ['a', 'b'], ['b', 'a']
    assert observe_dryrun(a).effects != observe_dryrun(b).effects


def test_malformed_response_is_an_error():
    with pytest.raises(ValueError):
        observe_dryrun({'txns': [{}]})


def _simulation(trace, inner=()):
    return {'version': 2, 'last-round': 0,
            'exec-trace-config': {'enable': True, 'scratch-change': True, 'state-change': True},
            'txn-groups': [{'txn-results': [{
                'txn-result': {'txn': {'txn': {'type': 'appl', 'apid': 7}}, 'inner-txns': list(inner)},
                'exec-trace': {'approval-program-trace': trace, 'inner-trace': [{} for _ in inner]},
            }]}]}


def test_simulation_compares_final_scratch_and_box_values_not_program_counters():
    from tests.behavioral_lift.observations import observe_simulate
    def step(pc, n):
        return {'pc': pc, 'scratch-changes': [{'slot': 2, 'new-value': {'type': 2, 'uint': n}}],
                'state-changes': [{'app-state-type': 'b', 'key': 'Yg==', 'operation': 'w',
                                   'new-value': {'type': 1, 'bytes': 'eA=='}}]}
    a = observe_simulate(_simulation([step(1, 0), step(5, 3)]))
    b = observe_simulate(_simulation([step(19, 3)]))
    assert a.effects == b.effects
    assert {'boxes', 'exported-scratch'} <= a.available
    assert a.effects != observe_simulate(_simulation([step(19, 4)])).effects


def test_simulation_observes_inner_transaction_fields_and_missing_traces():
    from tests.behavioral_lift.observations import observe_simulate
    def response(amount):
        return _simulation([{'pc': 8, 'spawned-inners': [0]}],
                           [{'txn': {'txn': {'type': 'pay', 'amt': amount}}}])
    a, b = map(observe_simulate, (response(1), response(2)))
    assert a.effects != b.effects
    missing = response(1)
    missing['exec-trace-config'] = {}
    assert 'exported-scratch' not in observe_simulate(missing).available


def test_simulation_missing_transaction_body_cannot_report_faithful():
    from tests.behavioral_lift.observations import observe_simulate
    response = _simulation([])
    response['txn-groups'][0]['txn-results'][0]['txn-result'] = {}
    result = compare_cases([0], lambda _: (observe_simulate(response), observe_simulate(response)), required=frozenset())
    assert result['status'] == 'INCONCLUSIVE' and result['errors'] == 1


def test_assembler_directives_and_pseudos_do_not_look_unknown():
    from tests.behavioral_lift.observations import required_effects
    assert 'unsupported-semantics' not in required_effects('#pragma version 10\n#pragma typetrack false\nbyte "x"\nlog\nint 1\nreturn')
