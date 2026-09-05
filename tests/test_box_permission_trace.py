"""Family marks are inferred from code and propagated on matched returns."""
import pytest

from tealql.tealtools.analysis.box_permissions import BoxApplication, BoxCallFrame, box_permission, trace_box_permissions
from tealql.tealtools.ssa import SSAProgram

APPS = [BoxApplication(1, 'family', False, True), BoxApplication(2, 'other', False, False),
        BoxApplication(3, 'family', False, True), BoxApplication(4, 'family', False, True)]


def _program(body):
    return SSAProgram.from_text('#pragma version 13\n' + body + '\nint 1\nreturn')


def _call(app):
    return f'itxn_begin\nint appl\nitxn_field TypeEnum\nint {app}\nitxn_field ApplicationID\nitxn_submit\n'


_READ = 'byte "key"\nbox_get\npop\npop\n'
_WRITE_FOREIGN = 'int 7\nbyte "key"\nbyte "value"\napp_box_put\n'


@pytest.mark.parametrize('read_first, allowed', [(False, True), (True, False)])
def test_infers_marked_family_ancestor_across_foreign_call(read_first, allowed):
    programs = {1: _program((_READ if read_first else '') + _call(2)),
                2: _program(_call(3)), 3: _program(_WRITE_FOREIGN)}
    result = trace_box_permissions(programs, APPS, 1, application_refs={3: {7: 1}})
    assert result.complete
    access = result.value[-1]
    assert access.permission.permitted is allowed
    assert access.permission.minimum_balance_owner == 1
    assert access.stack[0].family_state_used is read_first


def test_returned_family_access_marks_the_caller_for_later_calls():
    programs = {1: _program(_call(3) + _call(2)), 2: _program(_call(4)),
                3: _program(_READ), 4: _program(_WRITE_FOREIGN)}
    result = trace_box_permissions(programs, APPS, 1, application_refs={4: {7: 1}})
    assert result.complete
    access = result.value[-1]
    assert tuple(frame.app for frame in access.stack) == (1, 2, 4)
    assert access.stack[0].family_state_used
    assert access.permission.permitted is False


def test_marks_do_not_propagate_across_a_foreign_return():
    programs = {1: _program(_call(2) + _call(4)), 2: _program(_call(3)),
                3: _program(_READ), 4: _program(_WRITE_FOREIGN)}
    result = trace_box_permissions(programs, APPS, 1, application_refs={4: {7: 1}})
    assert result.complete and result.value[-1].permission.permitted
    assert not result.value[-1].stack[0].family_state_used


@pytest.mark.parametrize('options', [{'max_steps': 1}, {'max_depth': 0}, {}])
def test_missing_targets_and_budgets_never_report_complete(options):
    programs = {1: _program(_call(2))}
    result = trace_box_permissions(programs, APPS, 1, **options)
    assert not result.complete
    assert not result.value


def test_recursive_and_conditional_programs_are_unknown():
    assert not trace_box_permissions({1: _program(_call(1))}, APPS, 1).complete
    body = 'txn NumAppArgs\nbz done\n' + _READ + 'done:\n'
    assert not trace_box_permissions({1: _program(body)}, APPS, 1).complete


def test_known_rejection_stops_following_caller_accesses():
    programs = {1: _program(_call(2) + _READ), 2: _program('int 0\nassert\n')}
    result = trace_box_permissions(programs, APPS, 1)
    assert result.complete and not result.value


def test_unknown_foreign_owner_and_invalid_permission_flags_are_incomplete():
    assert not trace_box_permissions({1: _program(_WRITE_FOREIGN)}, APPS, 1).complete
    bad = [BoxApplication(1, 'family', False, 'false')]
    assert not trace_box_permissions({1: _program(_READ)}, bad, 1).complete
    assert not box_permission(APPS, [BoxCallFrame(1, 'false')], 1, write=True).complete
    assert not box_permission(APPS, [BoxCallFrame(1, False)], True, write=True).complete
