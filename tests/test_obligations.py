"""Bounded policy proofs have controls for missing, contradictory and stale evidence."""
import pytest

from tealql.security.obligations import (
    ObligationContext, analyze_obligations, authority_provenance, group_obligation,
    lifecycle_obligation, conservation_obligation, crypto_binding,
)
from tealql.security.compatibility import compare_contracts
from tealql.tealtools.analysis.box_permissions import (
    BoxApplication, BoxCallFrame, box_permission, inherit_family_mark, box_access_permissions,
)
from tealql.tealtools.analysis.relations import DifferenceConstraints
from tealql.tealtools.analysis.resource_requirements import resource_requirements
from tealql.tealtools.ssa import SSAProgram


def context(body, version=8):
    return ObligationContext(SSAProgram.from_text(f'#pragma version {version}\n' + body, name='policy.teal'))


def test_difference_relations_compose_and_do_not_explode_on_contradictions():
    solver = DifferenceConstraints([('a', 'le', ('+', 'b', 3)), ('b', 'le', ('-', 'c', 5))])
    assert solver.proves('a', 'le', ('-', 'c', 2))
    assert not solver.proves('a', 'lt', ('-', 'c', 2))
    assert not DifferenceConstraints([('x', 'lt', 'x')]).proves('a', 'eq', 'a')
    assert not DifferenceConstraints([('x', 'eq', 1)], max_atoms=1).proves('x', 'eq', 1)
    assert not solver.proves(('*', 'a', 'b'), 'eq', 0)


def test_difference_constraints_agree_with_bounded_integer_enumeration():
    from itertools import product
    for offset in range(-3, 4):
        premises = [('a', 'le', ('+', 'b', offset)), ('b', 'le', 4), ('a', 'ge', 0)]
        solver = DifferenceConstraints(premises)
        for bound in range(8):
            if solver.proves('a', 'le', bound):
                assert all(a <= bound for a, b in product(range(8), repeat=2)
                           if a <= b + offset and b <= 4)


@pytest.mark.parametrize('guard,initial,expected', [
    ('txn Sender\nglobal CreatorAddress\n==\nassert\n', True, 'PROVED'),
    ('txn Sender\nglobal CreatorAddress\n==\nassert\n', False, 'UNKNOWN'),
    ('', True, 'UNKNOWN'),
])
def test_authority_requires_all_writers_and_initial_state(guard, initial, expected):
    c = context(guard + 'byte "owner"\ntxn Sender\napp_global_put\nint 1\nreturn')
    result, = authority_provenance(c, ['owner'], initial_keys=['owner'] if initial else [])
    assert result.status == expected
    assert result.assumptions


@pytest.mark.parametrize('guard, expected', [
    ('txn Sender\nglobal CreatorAddress\n==\nassert\n', 'PROVED'), ('', 'UNKNOWN')])
def test_dynamic_writer_requires_authority_proof(guard, expected):
    c = context(guard +
                'txna ApplicationArgs 0\nint 1\napp_global_put\nint 1\nreturn')
    assert authority_provenance(c, ['owner'], initial_keys=['owner'])[0].status == expected


def test_group_relation_binds_amount_with_offset():
    c = context('global GroupSize\nint 1\n==\nassert\ngtxn 0 TypeEnum\nint 6\n==\nassert\n'
                'gtxn 0 Fee\nint 1000\n<=\nassert\nint 1\nreturn')
    policy = {'line': 15, 'size': 1, 'members': {'0': {'TypeEnum': 6}},
              'relations': [['gtxn 0 Fee', 'le', 1000]]}
    assert group_obligation(c, policy).status == 'PROVED'
    policy['relations'][0][2] = 999
    assert group_obligation(c, policy).status == 'UNKNOWN'
    policy['members'] = {}
    with pytest.raises(ValueError, match='every member'):
        group_obligation(c, policy)


def test_lifecycle_requires_elapsed_proposal_time_not_timestamp_presence():
    c = context('txn OnCompletion\nint 4\n==\nassert\n'
                'txn Sender\nglobal CreatorAddress\n==\nassert\n'
                'txn ApprovalProgram\nbyte "proposal"\napp_global_get\n==\nassert\n'
                'global LatestTimestamp\nbyte "proposed_at"\napp_global_get\nint 60\n+\n>=\nassert\nint 1\nreturn')
    reads = [a.location.line for a in c.program.assignments if a.op == 'app_global_get']
    line = next(a.location.line for a in c.program.assignments if a.op == 'return')
    policy = dict(line=line, delay=60, proposal_line=reads[0], proposed_at_line=reads[1], authority='global CreatorAddress')
    assert lifecycle_obligation(c, policy).status == 'PROVED'
    assert lifecycle_obligation(c, {**policy, 'delay': 61}).status == 'UNKNOWN'


def test_crypto_requires_exact_encoding_and_acceptance():
    c = context('byte "domain"\ntxn Fee\nitob\nconcat\nsha256\n'
                f'byte 0x{"00" * 64}\nbyte 0x{"00" * 32}\ned25519verify_bare\nassert\nint 1\nreturn')
    line = next(a.location.line for a in c.program.assignments if a.op == 'return')
    policy = dict(line=line, verify_line=9, domain='bytes:0x646f6d61696e', public_key='bytes:0x' + '00' * 32,
                  assumptions=['signature unforgeability, hash collision resistance, replay domain policy'],
                  fields=[{'value': 'bytes:0x646f6d61696e', 'width': 6}, {'value': 'txn Fee', 'width': 8}])
    assert crypto_binding(c, policy).status == 'PROVED'
    assert crypto_binding(c, {**policy, 'line': 9}).status == 'UNKNOWN'
    policy['fields'][1]['value'] = 'txn Amount'
    assert crypto_binding(c, policy).status == 'UNKNOWN'


def test_conservation_and_rounding_are_separate_obligations():
    c = context('int 10\nint 3\n/\nreturn')
    result, rounding = conservation_obligation(c, dict(line=5, unit='tokens',
        left=['+', 'txn Fee', 7], right=['+', 7, 'txn Fee']))
    assert result.status == 'PROVED'
    assert rounding.status == 'UNKNOWN' and 'remainder' in rounding.reason


APPS = [BoxApplication(1, 'creator', False, True), BoxApplication(2, 'foreign', True, False),
        BoxApplication(3, 'creator', False, True)]


@pytest.mark.parametrize('frames,write,allowed', [
    ([BoxCallFrame(1, True), BoxCallFrame(3, False)], True, True),
    ([BoxCallFrame(1, True), BoxCallFrame(2, False), BoxCallFrame(3, False)], True, False),
    ([BoxCallFrame(1, True), BoxCallFrame(2, False), BoxCallFrame(3, False)], False, True),
    ([BoxCallFrame(1, False), BoxCallFrame(2, False), BoxCallFrame(3, False)], True, True),
])
def test_family_permission_includes_marked_ancestor_rule(frames, write, allowed):
    result = box_permission(APPS, frames, 1, write=write)
    assert result.complete and result.value.permitted is allowed
    assert result.value.minimum_balance_owner == (1 if write else None)


def test_box_unknown_environment_and_inherited_marks():
    assert not box_permission(APPS, [], 1, write=True).complete
    assert not box_permission(APPS, [BoxCallFrame(9, False)], 1, write=True).complete
    assert inherit_family_mark(APPS, BoxCallFrame(1, False), BoxCallFrame(3, True)).family_state_used
    assert not inherit_family_mark(APPS, BoxCallFrame(2, False), BoxCallFrame(3, True)).family_state_used


def test_box_permissions_join_source_operands_with_owner_identity():
    c = context('int 7\nbyte "b"\napp_box_get\npop\npop\nint 1\nreturn', version=13)
    result = box_access_permissions(c.program, APPS, [BoxCallFrame(3, False)], application_refs={7: 1})
    assert result.complete
    access, = result.value
    assert access[0].line == 4 and access[1].value == '0x62'
    assert access[2].value.owner == 1 and access[2].value.permitted


def test_resource_classification_never_means_execution_sufficiency():
    requirements = resource_requirements(context('int 1\nreturn').program)
    assert {r.dimension for r in requirements} >= {'fees', 'opcode-budget', 'minimum-balance'}
    assert any(r.status == 'UNKNOWN' for r in requirements)


def test_revision_contracts_detect_schema_permission_and_effect_changes():
    before = dict(methods={'f': '(uint64)void'}, storage={'key': 'uint64'},
                  permissions={'f': 'creator'}, effects={'f': ['global-write']})
    after = {**before, 'storage': {'key': 'bytes'}, 'effects': {'f': ['global-write', 'box-delete']}}
    results = compare_contracts(before, after)
    assert {r.subject for r in results if r.status == 'REFUTED'} == {'storage:key', 'effects:f'}
    assert results[-1].status == 'UNKNOWN'
    with pytest.raises(ValueError):
        compare_contracts({}, {})


def test_empty_or_misspelled_policy_cannot_report_complete():
    program = context('int 1\nreturn').program
    assert not analyze_obligations(program, {})['complete']
    with pytest.raises(ValueError):
        analyze_obligations(program, {'group': []})


@pytest.mark.parametrize('annotation', ['txn Ffee', 'gtxn 16 Fee', 'txna Fee 0',
                                         'bytes:0x0', 'bytes:0xgg', {'line': 2, 'output': True}])
def test_invalid_annotation_cannot_prove_a_tautology(annotation):
    c = context('int 1\nreturn')
    with pytest.raises(ValueError):
        c.annotation(annotation)
