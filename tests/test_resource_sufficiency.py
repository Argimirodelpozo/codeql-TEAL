"""Resource upper bounds include allocation peaks and values read before resize."""
import pytest

from tealql.tealtools.analysis.resource_sufficiency import resource_sufficiency
from tealql.tealtools.ssa import SSAProgram


def _program(body):
    return SSAProgram.from_text('#pragma version 13\n' + body + '\nint 1\nreturn')


def _environment(**overrides):
    return dict(opcode_budget=700, fee_credit=10_000, spendable_balance=10_000_000,
                box_io_budget=10_000, inner_transaction_credit=256, boxes={'0x6b': None}) | overrides


def _rows(result):
    return {row.dimension: row for row in result.value}


def test_resource_bounds_use_real_box_allocation_and_instruction_cost():
    program = _program('byte "k"\nbyte "abc"\nbox_put\nbyte "k"\nbox_get\nassert\nlog')
    result = resource_sufficiency(program, _environment())
    rows = _rows(result)
    assert result.complete and all(row.status == 'PROVED' for row in result.value)
    assert rows['opcode-budget'].required == 11  # Includes two possible constant-table initializers.
    assert rows['spendable-balance'].required == 2500 + 400 * (1 + 3)
    assert rows['box-io'].required == 6
    assert rows['log-bytes'].required == 3
    assert rows['stack'].required == 2


@pytest.mark.parametrize('dimension, field, value', [
    ('opcode-budget', 'opcode_budget', 10), ('spendable-balance', 'spendable_balance', 4099),
    ('box-io', 'box_io_budget', 5),
])
def test_insufficient_credit_cannot_discharge_the_resource_obligation(dimension, field, value):
    program = _program('byte "k"\nbyte "abc"\nbox_put\nbyte "k"\nbox_get\nassert\nlog')
    environment = _environment()
    environment[field] = value
    result = resource_sufficiency(program, environment)
    assert _rows(result)[dimension].status == 'UNKNOWN'


def test_peak_minimum_balance_survives_a_later_box_delete():
    result = resource_sufficiency(_program('byte "k"\nint 100\nbox_create\npop\nbyte "k"\nbox_del\npop'), _environment())
    assert result.complete
    assert _rows(result)['spendable-balance'].required == 2500 + 400 * 101


def test_log_length_uses_the_value_read_before_resize():
    body = 'byte "k"\nbox_get\nassert\nstore 0\nbyte "k"\nint 1\nbox_resize\nload 0\nlog'
    environment = _environment()
    environment['boxes'] = {'0x6b': 1500}
    result = resource_sufficiency(_program(body), environment)
    assert result.complete
    assert _rows(result)['log-bytes'].required == 1500
    assert _rows(result)['log-bytes'].status == 'UNKNOWN'


def test_inner_payment_fees_and_balance_are_separate_bounds():
    body = ('itxn_begin\nint pay\nitxn_field TypeEnum\nint 7\nitxn_field Amount\n'
            'txn Sender\nitxn_field Receiver\nint 0\nitxn_field Fee\nitxn_submit')
    rows = _rows(resource_sufficiency(_program(body), _environment()))
    assert rows['fees'].required == 1000
    assert rows['spendable-balance'].required == 7
    assert rows['inner-count'].required == 1
    exhausted = resource_sufficiency(_program(body), _environment(inner_transaction_credit=0))
    assert _rows(exhausted)['inner-count'].status == 'UNKNOWN'


@pytest.mark.parametrize('body', [
    'txna ApplicationArgs 0\nlog',
    'txna ApplicationArgs 0\nbyte "v"\nbox_put',
    'int 7\nbyte "k"\napp_box_get\npop\npop',
    'itxn_begin\nint appl\nitxn_field TypeEnum\nint 7\nitxn_field ApplicationID\nitxn_submit',
    'txn NumAppArgs\nbnz done\nbyte "k"\nbox_del\npop\ndone:',
])
def test_unbounded_or_unmodelled_effects_never_publish_partial_totals(body):
    result = resource_sufficiency(_program(body), _environment())
    assert not result.complete
    assert all(row.required is None and row.status == 'UNKNOWN' for row in result.value)


def test_retry_witness_covers_resources_without_changing_initial_box_state():
    program = _program('byte "k"\nbyte "abc"\nbox_put')
    initial = _environment()
    initial['spendable_balance'] = 0
    result = resource_sufficiency(program, initial, retry=_environment())
    assert _rows(result)['spendable-balance'].status == 'UNKNOWN'
    assert _rows(result)['resource-retry'].status == 'PROVED'
    changed = _environment()
    changed['boxes'] = {'0x6b': 3}
    assert _rows(resource_sufficiency(program, initial, retry=changed))['resource-retry'].status == 'UNKNOWN'


def test_missing_reference_invalid_inventory_and_work_budget_are_unknown():
    program = _program('byte "k"\nbyte "abc"\nbox_put')
    for boxes in ({}, {'0x6b': -1}, {'invalid': 3}):
        environment = _environment()
        environment['boxes'] = boxes
        assert not resource_sufficiency(program, environment).complete
    assert not resource_sufficiency(program, _environment(), max_steps=1).complete


def test_shared_byte_expression_work_is_bounded():
    body = 'byte "k"\nbox_get\nassert\n' + 'dup\nconcat\n' * 30 + 'log'
    result = resource_sufficiency(_program(body), _environment(boxes={'0x6b': 1}))
    assert result.complete
    assert _rows(result)['log-bytes'].required == 2 ** 30
    assert _rows(result)['log-bytes'].status == 'UNKNOWN'


@pytest.mark.parametrize('environment', [None, [], {'boxes': []}, {'boxes': None}])
def test_invalid_environment_schema_is_rejected(environment):
    with pytest.raises(ValueError, match='must be maps'):
        resource_sufficiency(_program(''), environment)
