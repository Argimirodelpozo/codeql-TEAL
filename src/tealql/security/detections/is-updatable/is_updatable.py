"""sec-guide/is-updatable: one finding per approval exit not guarded against
``OnCompletion == UpdateApplication``.
"""
from __future__ import annotations

from tealql.security import common
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class IsUpdatableViolation(_ExitBBViolation):
    headline = "Application is updatable"
    detail = "OnCompletion == UpdateApplication can reach approval without a guard."


class IsUpdatableDetector(_ApprovalActionGuardDetector):
    name = "sec-guide/is-updatable"
    # A PROPERTY, not a vulnerability — upgradeable is usually deliberate.
    # Whether ANYONE can update it is the real bug: unprotected-updatable.
    severity = "informational"
    action = common.ONC_UPDATE_APPLICATION
    violation_cls = IsUpdatableViolation
