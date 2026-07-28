"""sec-guide/unprotected-deletable: an approval exit reachable with ``OnCompletion
== DeleteApplication`` and no covering sender==creator check — anyone can delete
the application.
"""
from __future__ import annotations

from tealql.security import common
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class UnprotectedDeletableViolation(_ExitBBViolation):
    headline = "Application is deletable by anyone"
    detail = "no sender == creator check guards the approval path for DeleteApplication."


class UnprotectedDeletableDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/unprotected-deletable"
    action = common.ONC_DELETE_APPLICATION
    creator_guard = "require_absent"
    violation_cls = UnprotectedDeletableViolation
