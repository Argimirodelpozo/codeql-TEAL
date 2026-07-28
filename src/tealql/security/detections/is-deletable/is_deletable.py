"""sec-guide/is-deletable: one finding per approval exit not guarded against
``OnCompletion == DeleteApplication``.
"""
from __future__ import annotations

from tealql.security import common
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class IsDeletableViolation(_ExitBBViolation):
    headline = "Application is deletable"
    detail = "OnCompletion == DeleteApplication can reach approval without a guard."


class IsDeletableDetector(_ApprovalActionGuardDetector):
    name = "sec-guide/is-deletable"
    # A PROPERTY, not a vulnerability — deletable is usually deliberate. Whether
    # ANYONE can delete it is the real bug, and that is unprotected-deletable.
    severity = "informational"
    action = common.ONC_DELETE_APPLICATION
    violation_cls = IsDeletableViolation
