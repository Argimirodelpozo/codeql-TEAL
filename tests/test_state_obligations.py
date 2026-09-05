"""Temporal proofs reject intervening changes, resets, and inconsistent pairs."""
import pytest

from tealql.security.obligations import ObligationContext, analyze_obligations
from tealql.security.state_obligations import authority_freshness, proposal_invariant, replay_protection
from tealql.tealtools.ssa import SSAProgram


def _context(body):
    return ObligationContext(SSAProgram.from_text('#pragma version 10\n' + body, name='state-proof.teal'))


def _line(context, op, index=0):
    return [a.location.line for a in context.program.assignments if a.op == op][index]


@pytest.mark.parametrize('intervening, expected', [
    ('', 'PROVED'),
    ('byte "other"\nint 7\napp_global_put\n', 'PROVED'),
    ('byte "owner"\nglobal CreatorAddress\napp_global_put\n', 'UNKNOWN'),
    ('txna ApplicationArgs 0\nglobal CreatorAddress\napp_global_put\n', 'UNKNOWN'),
    ('again:\ntxn NumAppArgs\nbnz again\n', 'UNKNOWN'),
])
def test_authority_read_must_still_be_current_at_guarded_use(intervening, expected):
    c = _context('byte "owner"\napp_global_get\nstore 0\n' + intervening +
                 'txn Sender\nload 0\n==\nassert\nint 1\nreturn')
    policy = {'read_line': _line(c, 'app_global_get'), 'line': _line(c, 'return')}
    result = authority_freshness(c, policy)
    assert result.status == expected
    assert result.assumptions


def test_authority_update_after_selected_use_does_not_make_that_use_stale():
    c = _context('byte "owner"\napp_global_get\nstore 0\ntxn Sender\nload 0\n==\nassert\n'
                 'byte "used"\nlog\nbyte "owner"\nglobal CreatorAddress\napp_global_put\nint 1\nreturn')
    result = authority_freshness(c, {'read_line': _line(c, 'app_global_get'), 'line': _line(c, 'log')})
    assert result.status == 'PROVED'


def _replay(*, key_field='Fee', nonce_guard=True, signature_guard=True, marker=1,
            write_key='load 0', consume_first=True, extra_writer=''):
    check = 'int 0\n==\nassert\n' if nonce_guard else 'pop\n'
    verify = 'assert\n' if signature_guard else 'pop\n'
    consume = write_key + f'\nint {marker}\napp_global_put\n'
    effect = 'byte "accepted"\nlog\n'
    c = _context(f'txn {key_field}\nitob\ndup\nstore 0\napp_global_get\n' + check +
                 'byte "domain"\ntxn Fee\nitob\nconcat\nsha256\n' +
                 'byte 0x' + '00' * 64 + '\nbyte 0x' + '00' * 32 + '\ned25519verify_bare\n' + verify +
                 (consume + effect if consume_first else effect + consume) + extra_writer + 'int 1\nreturn')
    policy = dict(line=_line(c, 'log'), read_line=_line(c, 'app_global_get'),
                  consume_line=_line(c, 'app_global_put'), verify_line=_line(c, 'ed25519verify_bare'),
                  domain='bytes:0x646f6d61696e', public_key='bytes:0x' + '00' * 32,
                  assumptions=['signature unforgeability and hash collision resistance'],
                  fields=[{'value': 'bytes:0x646f6d61696e', 'width': 6}, {'value': 'txn Fee', 'width': 8}])
    return c, policy


@pytest.mark.parametrize('mutation, expected', [
    ({}, 'PROVED'),
    ({'key_field': 'Amount'}, 'UNKNOWN'),
    ({'nonce_guard': False}, 'UNKNOWN'),
    ({'signature_guard': False}, 'UNKNOWN'),
    ({'marker': 0}, 'UNKNOWN'),
    ({'write_key': 'load 0\nsha256'}, 'UNKNOWN'),
    ({'consume_first': False}, 'UNKNOWN'),
    ({'extra_writer': 'load 0\nint 0\napp_global_put\n'}, 'UNKNOWN'),
    ({'extra_writer': 'load 0\napp_global_del\n'}, 'UNKNOWN'),
    ({'extra_writer': 'txna ApplicationArgs 0\nint 1\napp_global_put\n'}, 'PROVED'),
])
def test_replay_proof_needs_signed_key_zero_check_consumption_and_no_reset(mutation, expected):
    c, policy = _replay(**mutation)
    result = replay_protection(c, policy)
    assert result.status == expected
    assert 'persist' in result.assumptions[-2]
    report = analyze_obligations(c.program, {'replay': [policy]})
    assert report['complete'] == (expected == 'PROVED')


def test_monotone_consumption_matches_independent_invocation_sequences():
    from itertools import product
    for inputs in product(range(3), repeat=5):
        ledger = {}
        accepted = []
        for nonce in inputs:
            if ledger.get(nonce, 0) == 0:
                ledger[nonce] = 1
                accepted.append(nonce)
        assert len(accepted) == len(set(inputs))
        assert len(accepted) == len(set(accepted))


def _proposal(*, writer_guard=True, time_source='global LatestTimestamp', omit_time=False, extra=''):
    guard = 'txn Sender\nglobal CreatorAddress\n==\nassert\n'
    time_write = '' if omit_time else 'byte "proposed_at"\n' + time_source + '\napp_global_put\n'
    c = _context('txn OnCompletion\nint 4\n==\nbnz upgrade\n' + (guard if writer_guard else '') +
                 'byte "proposal"\ntxna ApplicationArgs 0\napp_global_put\n' + time_write + extra +
                 'int 1\nreturn\nupgrade:\n' + guard +
                 'txn ApprovalProgram\nbyte "proposal"\napp_global_get\n==\nassert\n'
                 'global LatestTimestamp\nbyte "proposed_at"\napp_global_get\nint 60\n+\n>=\nassert\nint 1\nreturn')
    return c, dict(line=_line(c, 'return', -1), proposal_line=_line(c, 'app_global_get'),
                   proposed_at_line=_line(c, 'app_global_get', 1), delay=60, authority='global CreatorAddress')


@pytest.mark.parametrize('mutation, expected', [
    ({}, 'PROVED'), ({'writer_guard': False}, 'UNKNOWN'),
    ({'time_source': 'int 0'}, 'UNKNOWN'), ({'omit_time': True}, 'UNKNOWN'),
    ({'extra': 'txna ApplicationArgs 1\nint 0\napp_global_put\n'}, 'UNKNOWN'),
    ({'extra': 'byte "proposal"\napp_global_del\n'}, 'UNKNOWN'),
])
def test_upgrade_infers_all_pair_writers_and_creator_permission(mutation, expected):
    c, policy = _proposal(**mutation)
    assert proposal_invariant(c, policy).status == expected


def test_upgrade_delay_and_distinct_pair_keys_are_required():
    c, policy = _proposal()
    assert proposal_invariant(c, {**policy, 'delay': 61}).status == 'UNKNOWN'
    assert proposal_invariant(c, {**policy, 'proposed_at_line': policy['proposal_line']}).status == 'UNKNOWN'
