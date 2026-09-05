"""Pinned local interpreter checks over benign arithmetic and observable state.

Opt-in; when requested, an unavailable node or missing SDK is a failure.
"""
import os

import pytest

from tests.behavioral_lift.compare import _compile, PROTOCOL
from tests.behavioral_lift.simulate import simulate_creation
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
