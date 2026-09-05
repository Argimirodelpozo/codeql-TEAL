"""Pinned local interpreter checks over benign arithmetic and observable state.

Opt-in; when requested, an unavailable node or missing SDK is a failure.
"""
import os

import pytest

from tests.behavioral_lift.compare import _compile, PROTOCOL
from tests.behavioral_lift.simulate import (
    compare_groups, existing_app_group, parameters, simulate_creation,
)
from tests.behavioral_lift.observations import compare_cases, required_effects
from tests.behavioral_lift.recompile import algod_client, lift_to_teal

pytestmark = pytest.mark.skipif(os.environ.get('TEALQL_LOCALNET') != '1', reason='requires pinned private localnet')


@pytest.fixture(scope='module')
def node():
    client = algod_client()
    assert client.status()['last-version'] == PROTOCOL
    genesis = client.genesis()
    if isinstance(genesis, str):
        import json
        genesis = json.loads(genesis)
    allocation = max(genesis['alloc'], key=lambda a: a['state']['algo'])
    return client, allocation['addr'], client.status()['last-round']


@pytest.mark.parametrize('body', [
    'txn Fee\nint 3\n%\nitob\nlog',
    'byte "counter"\nint 7\napp_global_put',
    'int 0\nbyte "counter"\nint 7\napp_local_put',
    'int 9223372036854775808\nint 1\nshl\nitob\nlog',
])
def test_lift_preserves_successful_observations(node, tmp_path, body):
    client, sender, round = node
    source = '#pragma version 10\n' + body + '\nint 1\nreturn\n'
    path = tmp_path / 'observation.teal'
    path.write_text(source)
    lifted = lift_to_teal(str(path))
    original, compiled = _compile(client, source), _compile(client, lifted)
    clear = _compile(client, '#pragma version 10\nint 1')
    result = compare_cases([([], 0)], lambda _: (
        simulate_creation(client, original, clear, sender=sender, round=round, on_complete=1 if "app_local_put" in body else 0),
        simulate_creation(client, compiled, clear, sender=sender, round=round, on_complete=1 if "app_local_put" in body else 0)),
        required=required_effects(source, lifted))
    assert result['status'] == 'FAITHFUL', result
    assert result['completed'] == result['approve'] == 1


def test_oracle_detects_changed_committed_state(node):
    client, sender, round = node
    clear = _compile(client, '#pragma version 10\nint 1')
    codes = [_compile(client, f'#pragma version 10\nbyte "counter"\nint {n}\napp_global_put\nint 1') for n in (7, 8)]
    result = compare_cases([0], lambda _: tuple(simulate_creation(client, code, clear, sender=sender, round=round) for code in codes),
                           required=frozenset({'global'}))
    assert result['status'] == 'DIVERGES' and result['completed'] == 1


@pytest.mark.parametrize('size', [64, 65])
def test_numeric_byte_comparison_width_matches_the_private_interpreter(node, size):
    from tealql.tealtools.ssa import SSAProgram
    from tests.behavioral_lift.simulate import creation, simulate_transactions
    from tests.behavioral_lift.observations import observe_simulate
    client, sender, round = node
    source = '#pragma version 13\nbyte 0x' + '00' * (size - 1) + '01\nbyte 0x01\nb==\nreturn'
    program = SSAProgram.from_text(source)
    comparison = next(a for a in program.assignments if a.op == 'b==')
    value = program.facts().constant(comparison.outputs[0])
    # Supply the same bytes at runtime: the assembler itself rejects a known
    # 65-byte literal at b== before it can reach the interpreter.
    code = _compile(client, '#pragma version 13\ntxna ApplicationArgs 0\nbyte 0x01\nb==\nreturn')
    txn = creation(client, code, _compile(client, '#pragma version 13\nint 1'), sender=sender, round=round)
    txn.app_args = [bytes(size - 1) + b'\x01']
    observed = observe_simulate(simulate_transactions(client, [txn], round=round))
    assert observed.approved is (size == 64), observed
    assert (value is not None) is (size == 64)
    if size == 65:
        assert 'large byte-array' in observed.detail


def test_source_resource_bound_covers_assembler_constant_tables(node):
    from tealql.tealtools.analysis.resource_sufficiency import resource_sufficiency
    from tealql.tealtools.ssa import SSAProgram
    from tests.behavioral_lift.simulate import creation, simulate_transactions
    client, sender, round = node
    source = '#pragma version 13\n' + 'int 7\nitob\nlog\n' * 4 + 'int 1\nreturn'
    report = resource_sufficiency(SSAProgram.from_text(source), {
        'opcode_budget': 700, 'fee_credit': 0, 'spendable_balance': 0, 'box_io_budget': 0, 'boxes': {}})
    assert report.complete and all(row.status == 'PROVED' for row in report.value)
    code, clear = _compile(client, source), _compile(client, '#pragma version 13\nint 1')
    response = simulate_transactions(client, [creation(client, code, clear, sender=sender, round=round)], round=round)
    group = response['txn-groups'][0]
    assert not group.get('failure-message'), group
    required = next(row.required for row in report.value if row.dimension == 'opcode-budget')
    assert 14 < group['app-budget-consumed'] <= required


@pytest.mark.parametrize('body, equivalent', [
    ('int 2\nint 3\n+\nitob\nlog\nint 1\nreturn', True),
    ('byte "changed"\nlog\nint 1\nreturn', False),
])
def test_revision_comparison_matches_private_constant_execution(node, body, equivalent):
    from tealql.security.compatibility import compare_programs
    from tealql.tealtools.ssa import SSAProgram
    client, sender, round = node
    before = '#pragma version 13\nbyte 0x0000000000000005\nlog\nint 1\nreturn'
    after = '#pragma version 13\n' + body
    result = compare_programs(SSAProgram.from_text(before), SSAProgram.from_text(after))
    assert result.status == ('PROVED' if equivalent else 'REFUTED')
    clear = _compile(client, '#pragma version 13\nint 1')
    observations = [simulate_creation(client, _compile(client, source), clear, sender=sender, round=round)
                    for source in (before, after)]
    assert all(observation.approved for observation in observations)
    assert (observations[0].effects == observations[1].effects) is equivalent


_EXISTING = {
    'global': '''
txn ApplicationID
bz create
byte "counter"
dup
app_global_get
txna ApplicationArgs 0
btoi
+
dup
itob
log
app_global_put
int 1
return
create:
byte "counter"
int 7
app_global_put
int 1
return
''',
    'boxes': '''
txn ApplicationID
bz done
txna ApplicationArgs 0
byte "put"
==
bnz put
txna ApplicationArgs 0
byte "delete"
==
bnz delete
byte "record"
box_get
assert
log
b done
put:
byte "record"
txna ApplicationArgs 1
box_put
b done
delete:
byte "record"
box_del
assert
done:
int 1
return
''',
    'inner': '''
txn ApplicationID
bz done
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
txna ApplicationArgs 0
btoi
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
itxn Amount
itob
log
done:
int 1
return
''',
    'scratch': '''
txn ApplicationID
bz done
txn GroupIndex
int 1
==
bnz write
gload 1 42
itob
log
b done
write:
int 42
store 42
done:
int 1
return
''',
    'lifecycle': '''
txn ApplicationID
bz done
txn OnCompletion
int OptIn
==
bnz optin
txn OnCompletion
int NoOp
==
bz authority
int 0
byte "counter"
app_local_get
txna ApplicationArgs 0
btoi
+
dup
itob
log
int 0
byte "counter"
uncover 2
app_local_put
b done
optin:
int 0
byte "counter"
int 4
app_local_put
b done
authority:
txn Sender
global CreatorAddress
==
assert
done:
int 1
return
''',
    'group': '''
txn ApplicationID
bz done
global GroupSize
int 3
==
assert
gtxn 1 TypeEnum
int pay
==
assert
gtxn 1 Receiver
global CurrentApplicationAddress
==
assert
gtxn 1 Amount
itob
log
done:
int 1
return
''',
}


def _steps(client, sender, round, name, clear, replacement):
    from algosdk import logic, transaction as t
    def steps(app):
        def call(*args, oc=0, **kwargs):
            return t.ApplicationCallTxn(sender, parameters(client, round, fee=2000 if name == 'inner' else 1000),
                                        app, oc, app_args=list(args), **kwargs)
        funding = [t.PaymentTxn(sender, parameters(client, round), logic.get_application_address(app), 2_000_000)]
        if name == 'global':
            return [call(n.to_bytes(8, 'big')) for n in (3, 9)]
        if name == 'boxes':
            return funding + [call(*args, boxes=[(app, b'record')]) for args in
                              [(b'put', b'first'), (b'get',), (b'put', b'other'), (b'get',), (b'delete',)]]
        if name == 'inner':
            return funding + [call(n.to_bytes(8, 'big')) for n in (1, 2)]
        if name == 'scratch':
            return [call(), call()]
        if name == 'lifecycle':
            return [call(oc=1), call((3).to_bytes(8, 'big')), call(oc=2), call(oc=1), call(oc=3),
                    call(oc=4, approval_program=replacement, clear_program=clear), call(), call(oc=5)]
        assert name == 'group'
        return funding + [call()]
    return steps


@pytest.mark.parametrize('name, expected_logs', [
    ('global', [(10).to_bytes(8, 'big'), (19).to_bytes(8, 'big')]),
    ('boxes', [b'first', b'other']),
    ('inner', [(1).to_bytes(8, 'big'), (2).to_bytes(8, 'big')]),
    ('scratch', [(42).to_bytes(8, 'big')]),
    ('lifecycle', [(7).to_bytes(8, 'big'), b'cleared', b'updated', b'updated']),
    ('group', [(2_000_000).to_bytes(8, 'big')]),
])
def test_lift_preserves_existing_state_and_group_effects(node, tmp_path, name, expected_logs):
    import base64
    import json
    client, sender, round = node
    source = '#pragma version 10\n' + _EXISTING[name]
    path = tmp_path / f'{name}.teal'
    path.write_text(source)
    lifted = lift_to_teal(str(path))
    clear = _compile(client, '#pragma version 10\nbyte "cleared"\nlog\nint 1')
    replacement = _compile(client, '#pragma version 10\nbyte "updated"\nlog\nint 1')
    steps = _steps(client, sender, round, name, clear, replacement)
    groups = [existing_app_group(client, _compile(client, code), clear, steps, sender=sender, round=round)
              for code in (source, lifted)]
    observations = compare_groups(client, *groups, round=round)
    result = compare_cases([name], lambda _: observations,
                           required=required_effects(source, lifted) | {'existing-app-state', 'transaction-groups'})
    assert result['status'] == 'FAITHFUL', (result, observations)
    effects = json.loads(observations[0].effects)
    logs = [base64.b64decode(value) for row in effects['transactions'] for value in row['logs']]
    assert logs == expected_logs
    assert client.status()['last-round'] == round  # The fixture never commits.


@pytest.mark.parametrize('body, expected', [
    ('''int 0
store 0
loop:
load 0
int 10
<
bz done
load 0
int 4
+
store 0
b loop
done:
load 0
itob
log
int 1
return''', [12]),
    ('''int 3
callsub twice
int 7
callsub twice
+
itob
log
int 1
return
twice:
proto 1 1
frame_dig -1
int 2
*
retsub''', [20]),
    ('''int 4
callsub pair
itob
log
itob
log
int 1
return
pair:
proto 1 2
frame_dig -1
int 1
+
frame_dig -1
int 2
*
retsub''', [8, 5]),
    ('''int 3
callsub replace
itob
log
int 1
return
replace:
proto 1 1
frame_dig -1
int 1
+
frame_bury -1
frame_dig -1
retsub''', [4]),
    ('''int 11
int 22
int 33
int 44
callsub residual
itob
log
itob
log
itob
log
int 1
return
residual:
proto 1 0
int 2
int 3
mulw
cover 4
retsub''', [22, 6, 11]),
], ids=['loop-stride', 'separate-calls', 'multiple-returns', 'frame-replacement', 'wide-residual'])
def test_numeric_fragments_against_interpreter(node, tmp_path, body, expected):
    import base64
    import json
    client, sender, round = node
    source = '#pragma version 10\n' + body + '\n'
    path = tmp_path / 'numeric.teal'
    path.write_text(source)
    lifted = lift_to_teal(str(path))
    clear = _compile(client, '#pragma version 10\nint 1')
    observations = tuple(simulate_creation(client, _compile(client, code), clear, sender=sender, round=round)
                         for code in (source, lifted))
    result = compare_cases([0], lambda _: observations, required=required_effects(source, lifted))
    assert result['status'] == 'FAITHFUL', (result, observations)
    assert [int.from_bytes(base64.b64decode(value), 'big') for value in json.loads(observations[0].effects)['logs']] == expected
