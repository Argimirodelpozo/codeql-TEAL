"""Implementation comparison preserves concrete outcomes and possible traps."""
from itertools import product

import pytest

from tealql.security.compatibility import compare_programs
from tealql.tealtools.ssa import SSAProgram


def _program(body, *, version=13):
    return SSAProgram.from_text(f'#pragma version {version}\n{body}\n', name='revision.teal')


def _compare(before, after, **kwargs):
    return compare_programs(_program(before), _program(after), **kwargs)


@pytest.mark.parametrize('before, after', [
    ('int 2\nint 3\n+\nitob\nlog\nint 1\nreturn', 'byte 0x0000000000000005\nlog\nint 1\nreturn'),
    ('txn Fee\ntxn FirstValid\n+\nitob\nlog\nint 1\nreturn', 'txn FirstValid\ntxn Fee\n+\nitob\nlog\nint 1\nreturn'),
    ('txn Fee\ndup\n+\nreturn', 'txn Fee\ntxn Fee\n+\nreturn'),
    ('int 9\nstore 0\nload 0\nreturn', 'int 9\ndup\nstore 0\nreturn'),
    ('load 0\n!\nreturn', 'int 1\nreturn'),
    ('byte "k"\nint 7\napp_global_put\nint 1\nreturn', 'byte "k"\nint 3\nint 4\n+\napp_global_put\nint 1\nreturn'),
    ('intcblock 1 7\nintc_1\nreturn', 'int 7\nreturn'),
    ('int 2\nint 3\naddw\nitob\nlog\nitob\nlog\nint 1\nreturn',
     'byte 0x0000000000000005\nlog\nbyte 0x0000000000000000\nlog\nint 1\nreturn'),
    ('byte "discarded"\nlog\nint 0\nreturn', 'err'),
])
def test_supported_stack_and_literal_equivalences(before, after):
    result = _compare(before, after)
    assert result.status == 'PROVED', result
    assert result.assumptions


@pytest.mark.parametrize('before, after', [
    ('int 1\nreturn', 'int 0\nreturn'),
    ('byte "old"\nlog\nint 1\nreturn', 'byte "new"\nlog\nint 1\nreturn'),
    ('byte "a"\nlog\nbyte "b"\nlog\nint 1\nreturn', 'byte "b"\nlog\nbyte "a"\nlog\nint 1\nreturn'),
    ('int 1\nreturn', 'int 0\nassert\nint 1\nreturn'),
])
def test_fully_constant_difference_is_refuted(before, after):
    assert _compare(before, after).status == 'REFUTED'


@pytest.mark.parametrize('body', [
    'int 18446744073709551615\nint 1\n+\npop',
    'int 1\nint 0\n/\npop',
    'byte "x"\nint 9\ngetbyte\npop',
    'int 1\nint 1\nb==\npop',
    'byte 0x' + '00' * 65 + '\nbyte 0x00\nb==\npop',
    'byte "k"\napp_global_get\npop',
    'txn FirstValidTime\npop',
    'txn NumLogs\npop',
    'txn LastLog\npop',
    'txn CreatedAssetID\npop',
    'txn CreatedApplicationID\npop',
    'global LatestTimestamp\npop',
    'global CreatorAddress\npop',
    'int 9\nstore 0',
    'byte "k"\nint 9\napp_global_put',
])
def test_discarded_effects_or_trapping_expressions_are_not_eliminated(body):
    assert _compare(body + '\nint 1\nreturn', 'int 1\nreturn').status == 'UNKNOWN'


@pytest.mark.parametrize('body', [
    'txn Fee\nbnz done\nint 0\nreturn\ndone:\nint 1\nreturn',
    'callsub helper\nreturn\nhelper:\nint 1\nretsub',
    'global OpcodeBudget\nreturn',
    'byte "m"\nbyte 0x' + '00' * 64 + '\nbyte 0x' + '00' * 32 + '\ned25519verify\nreturn',
    'itxn_begin\nint pay\nitxn_field TypeEnum\nitxn_submit\nint 1\nreturn',
    'int 0\napp_params_get AppApprovalProgram\nassert\npop\nint 1\nreturn',
    'intc_0\nintcblock 1\nreturn',
])
def test_unsupported_observations_and_control_flow_refuse_even_identical_sources(body):
    assert _compare(body, body).status == 'UNKNOWN'


def test_instruction_version_and_stack_budgets():
    body = 'int 1\nreturn'
    assert _compare(body, body, max_steps=1).status == 'UNKNOWN'
    assert compare_programs(_program(body, version=12), _program(body)).status == 'UNKNOWN'
    overflow = 'load 0\n' * 1001 + 'popn 255\npopn 255\npopn 255\npopn 236\nint 1\nreturn'
    assert _compare(overflow, body, max_steps=1100).status == 'UNKNOWN'


def test_shared_symbolic_arithmetic_dag_is_not_expanded():
    body = 'txn Fee\n' + 'dup\n+\n' * 40 + 'return'
    assert _compare(body, body).status == 'PROVED'


def test_constant_arithmetic_against_independent_integer_oracle():
    # Python computes the expected outcomes without consulting the SSA folder.
    # Unsafe uint64 operations must retain a trap event instead of matching an
    # unconditional approving revision.
    for left, right, op in product((0, 1, 7, 2 ** 63, 2 ** 64 - 1), (0, 1, 3), ('+', '-', '*', '/', '%')):
        body = f'int {left}\nint {right}\n{op}\nitob\nlog\nint 1\nreturn'
        try:
            expected = {'+': lambda: left + right, '-': lambda: left - right,
                        '*': lambda: left * right, '/': lambda: left // right,
                        '%': lambda: left % right}[op]()
            valid = 0 <= expected < 2 ** 64
        except ZeroDivisionError:
            valid = False
        reference = (f'byte 0x{expected:016x}\nlog\nint 1\nreturn' if valid else 'int 1\nreturn')
        assert _compare(body, reference).status == ('PROVED' if valid else 'UNKNOWN')
