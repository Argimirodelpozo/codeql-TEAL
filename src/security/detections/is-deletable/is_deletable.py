"""sec-guide/is-deletable: app can reach approval with OnCompletion=DeleteApplication.

One finding per approval exit not guarded against ``OnCompletion == 5``.
Deliberately over-conservative: guards expressed via ``match`` / ``switch``
dispatch tables aren't recognised; explicit ``OnCompletion == K`` (or
``!=``) checks that control the path to the exit are.
"""
from __future__ import annotations

from security import common
from security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class IsDeletableViolation(_ExitBBViolation):
    headline = "Application is deletable"
    detail = "OnCompletion == DeleteApplication can reach approval without a guard."


class IsDeletableDetector(_ApprovalActionGuardDetector):
    name = "sec-guide/is-deletable"
    # A PROPERTY, not a vulnerability: a deletable app is usually deletable on
    # purpose (the creator can tear it down). Whether *anyone* can delete it
    # without authorization is the real bug — that's unprotected-deletable.
    severity = "informational"
    action = common.ONC_DELETE_APPLICATION
    violation_cls = IsDeletableViolation
