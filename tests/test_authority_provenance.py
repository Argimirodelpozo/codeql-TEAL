"""Authority preservation is distinct from assumed ledger initialization."""
import pytest

from tealql.security import DETECTORS
from tealql.tealtools.analysis.authority import authority_for, authority_health
from tealql.tealtools.lift import build_lifter
from tealql.tealtools.ssa import SSAProgram


CREATOR = 'txn Sender\nglobal CreatorAddress\n==\nassert\n'
READ = 'byte "admin"\napp_global_get\n'
WRITE = 'byte "admin"\ntxna ApplicationArgs 0\napp_global_put\n'


def program(body, name='authority.teal'):
    return SSAProgram.from_text('#pragma version 8\n' + body, name=name)


def stored_address(prog):
    return next(a.outputs[0] for a in reversed(prog.assignments) if a.op == 'app_global_get')


@pytest.mark.parametrize('reference, trusted', [
    ('int 0', True), ('txn ApplicationID', True), ('global CurrentApplicationID', True),
    ('txna Applications 0', True), ('int 0\ntxnas Applications', True),
    ('txna Applications 1', False), ('txn NumAppArgs\ntxnas Applications', False),
    ('int 99', False),
])
def test_only_current_app_creator_is_an_immutable_authority(reference, trusted):
    prog = program(reference + '\napp_params_get AppCreator\npop\nlog\nint 1\nreturn')
    read = next(a for a in prog.assignments if a.op == 'app_params_get')
    analysis = authority_for(prog)
    assert not analysis.address(read.outputs[0]).preserved  # existence is not an address
    assert analysis.address(read.outputs[1]).proved is trusted


@pytest.mark.parametrize('literal, trusted', [('00' * 32, True), ('01' * 32, True), ('00', False)])
def test_fixed_sender_identities_include_the_zero_address(literal, trusted):
    prog = program('txn Sender\nbyte 0x' + literal + '\n==\nreturn')
    detector = DETECTORS['unprotected-updatable'](prog)
    assert bool(detector.detect()) is not trusted
    assert detector.degraded is None


@pytest.mark.parametrize('guard, trusted', [('', False), (CREATOR, True)])
def test_all_writers_must_preserve_authority(guard, trusted):
    prog = program(guard + WRITE + READ + 'log\nint 1\nreturn')
    analysis = authority_for(prog)
    result = analysis.address(stored_address(prog))
    assert result.preserved is trusted
    assert not result.proved
    if trusted:
        assert any('initial global key' in a for a in result.assumptions)
        assert not authority_health([result]).complete
    else:
        assert 'writer at' in result.reason


@pytest.mark.parametrize('guard, trusted', [('', False), (CREATOR, True)])
def test_dynamic_key_writers_need_the_same_authority_restriction(guard, trusted):
    prog = program(guard + 'txna ApplicationArgs 0\ntxna ApplicationArgs 1\napp_global_put\n'
                   + READ + 'log\nint 1\nreturn')
    assert authority_for(prog).address(stored_address(prog)).preserved is trusted


def test_creator_initialization_and_self_rotation_keep_history_premises():
    prog = program('txn ApplicationID\nbnz rotate\n' + WRITE + 'int 1\nreturn\n'
                   'rotate:\ntxn Sender\n' + READ + '==\nassert\n' + WRITE
                   + READ + 'log\nint 1\nreturn')
    result = authority_for(prog).address(stored_address(prog))
    assert result.preserved and not result.proved
    assert any('upgrades preserve' in a for a in result.assumptions)


def test_shared_authority_read_preserves_self_rotation_inductively():
    prog = program('txn Sender\ncallsub admin\n==\nassert\n' + WRITE +
                   'int 1\nreturn\nadmin:\nproto 0 1\n' + READ + 'retsub')
    result = authority_for(prog).state_key('authority.teal', 'global', b'admin')
    assert result.preserved and not result.proved


@pytest.mark.parametrize('sender', ['txna Accounts 0', 'int 0\ntxnas Accounts'])
def test_writer_guards_accept_current_sender_aliases(sender):
    prog = program(sender + '\nglobal CreatorAddress\n==\nassert\n' + WRITE +
                   READ + 'log\nint 1\nreturn')
    assert authority_for(prog).address(stored_address(prog)).preserved


def test_caller_seeds_cannot_establish_a_whole_program_writer_invariant():
    from tealql.tealtools.cfg.path_predicates import BranchCondition, PathPredicateAnalysis
    prog = program('txn Sender\npop\nglobal CreatorAddress\npop\n' + WRITE +
                   READ + 'log\nint 1\nreturn')
    sender = next(a.outputs[0] for a in prog.assignments if a.op == 'txn')
    creator = next(a.outputs[0] for a in prog.assignments if a.op == 'global')
    seeded = PathPredicateAnalysis(prog, entry_seeds=frozenset({BranchCondition(sender, 'eq', (creator,))}))
    analysis = authority_for(prog, paths=seeded)
    assert not analysis.address(stored_address(prog)).preserved
    assert not analysis.paths.entry_seeds


def test_one_unrestricted_replacement_invalidates_other_guarded_writers():
    prog = program('txn NumAppArgs\nint 2\n==\nbnz guarded\n' + WRITE
                   + 'b done\nguarded:\n' + CREATOR + WRITE + 'done:\n'
                   + READ + 'log\nint 1\nreturn')
    assert not authority_for(prog).address(stored_address(prog)).preserved


def test_fixed_creator_replacement_is_authority_preserving():
    prog = program('byte "admin"\nglobal CreatorAddress\napp_global_put\n'
                   + READ + 'log\nint 1\nreturn')
    assert authority_for(prog).address(stored_address(prog)).preserved


@pytest.mark.parametrize('app, trusted', [(0, True), (99, False)])
def test_foreign_state_and_existence_flags_are_not_local_authorities(app, trusted):
    prog = program(f'int {app}\nbyte "admin"\napp_global_get_ex\npop\nlog\nint 1\nreturn')
    read = next(a for a in prog.assignments if a.op == 'app_global_get_ex')
    analysis = authority_for(prog)
    assert not analysis.address(read.outputs[0]).preserved
    assert analysis.address(read.outputs[1]).preserved is trusted


def test_authority_writers_do_not_cross_file_identity(tmp_path):
    (tmp_path / 'a.teal').write_text('#pragma version 8\n' + WRITE + 'int 1\nreturn')
    (tmp_path / 'b.teal').write_text('#pragma version 8\n' + READ + 'log\nint 1\nreturn')
    prog = SSAProgram(str(tmp_path))
    result = authority_for(prog).address(stored_address(prog))
    assert result.preserved
    assert all('b.teal' in assumption for assumption in result.assumptions)


def test_revision_and_capture_boundaries_remain_explicit():
    prog = program(READ + 'log\nint 1\nreturn')
    value = stored_address(prog)
    analysis = authority_for(prog)
    with analysis.capture() as first:
        result = analysis.address(value)
    with analysis.capture() as second:
        assert analysis.address(value) is result
    assert len(first) == len(second) == 1 and first is not second
    assert analysis._captures == []
    prog.propagate_constants()
    with pytest.raises(RuntimeError, match='stale authority'):
        analysis.address(value)
    assert authority_for(prog) is not analysis


@pytest.mark.parametrize('writer, expected_findings', [('', False), (WRITE, True), (CREATOR + WRITE, False)])
def test_lifecycle_detector_uses_writer_provenance_and_reports_assumptions(writer, expected_findings):
    prog = program(writer + 'txn Sender\n' + READ + '==\nreturn')
    detector = DETECTORS['unprotected-updatable'](prog)
    assert bool(detector.detect()) is expected_findings
    if not writer:
        assert detector.degraded and 'initial global key' in detector.degraded
        assert detector.authority_evidence
    if writer == WRITE:
        assert detector.degraded is None


@pytest.mark.parametrize('writer, expected_findings', [('', False), (WRITE, True), (CREATOR + WRITE, False)])
def test_lifted_log_detector_uses_the_same_authority_contract(writer, expected_findings):
    prog = program(writer + 'txn Sender\n' + READ + '==\nassert\n'
                   'txna ApplicationArgs 1\nlog\nint 1\nreturn')
    assert build_lifter(prog) is not None
    detector = DETECTORS['tainted-log'](prog)
    assert bool(detector.detect()) is expected_findings
    if not writer:
        assert detector.degraded and detector.authority_evidence
        assert any(e.assumptions and e.relation == 'member-of-authority-set'
                   for e in detector.guard_evidence)


def test_default_runner_retains_conditional_authorization_status():
    from tealql.security.run import run_all_dict
    prog = program('txn Sender\n' + READ + '==\nreturn')
    result = run_all_dict(prog)
    assert not result['complete']
    assert any('initial global key' in n['message'] for n in result['notifications'])


@pytest.mark.parametrize('sender', [
    'txn Sender\ntxna ApplicationArgs 0\nb^\n',
    'txn NumAppArgs\nbz original\ntxna ApplicationArgs 0\nb join\n'
    'original:\ntxn Sender\njoin:\n',
])
def test_sender_dependency_is_not_an_exact_sender_identity(sender):
    prog = program(sender + 'global CreatorAddress\n==\nassert\n'
                   'txna ApplicationArgs 1\nlog\nint 1\nreturn')
    assert DETECTORS['tainted-log'](prog).detect()


def test_sender_copies_and_all_sender_join_arms_keep_identity():
    prog = program('txn NumAppArgs\nbz original\ntxna Accounts 0\nb join\n'
                   'original:\ntxn Sender\njoin:\nstore 0\nload 0\n'
                   'global CreatorAddress\n==\nassert\n'
                   'txna ApplicationArgs 1\nlog\nint 1\nreturn')
    assert not DETECTORS['tainted-log'](prog).detect()


def test_guard_evidence_distinguishes_input_dependency_from_authority_predicate():
    prog = program('txna ApplicationArgs 0\nbyte "ok"\n==\nassert\n'
                   'txna ApplicationArgs 0\nlog\nint 1\nreturn')
    detector = DETECTORS['tainted-log'](prog)
    assert not detector.detect()
    assert detector.guard_evidence and not any(e.is_proof for e in detector.guard_evidence)
    prog = program(CREATOR + 'txna ApplicationArgs 0\nlog\nint 1\nreturn')
    detector = DETECTORS['tainted-log'](prog)
    assert not detector.detect()
    assert any(e.is_proof and not e.assumptions for e in detector.guard_evidence)
