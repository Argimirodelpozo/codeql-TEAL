"""sec-guide/is-updatable: app can reach approval with OnCompletion=UpdateApplication.

One finding per approval exit not guarded against ``OnCompletion == 4``.
"""
from __future__ import annotations

from security import common
from security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class IsUpdatableViolation(_ExitBBViolation):
    headline = "Application is updatable"
    detail = "OnCompletion == UpdateApplication can reach approval without a guard."


class IsUpdatableDetector(_ApprovalActionGuardDetector):
    name = "sec-guide/is-updatable"
    # A PROPERTY, not a vulnerability: an upgradeable app is usually upgradeable
    # on purpose. Whether *anyone* can update it without authorization is the
    # real bug — that's unprotected-updatable.
    severity = "informational"
    action = common.ONC_UPDATE_APPLICATION
    violation_cls = IsUpdatableViolation
