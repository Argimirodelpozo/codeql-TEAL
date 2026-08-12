"""sec-guide/unprotected-updatable: an approval exit reachable with ``OnCompletion
== UpdateApplication`` and no covering sender==creator check — anyone can replace
the contract code.
"""
from __future__ import annotations

from tealql.security._action_guards import ONC_UPDATE_APPLICATION
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class UnprotectedUpdatableViolation(_ExitBBViolation):
    headline = "Application is updatable by anyone"
    detail = "no sender == creator check guards the approval path for UpdateApplication."


class UnprotectedUpdatableDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/unprotected-updatable"
    action = ONC_UPDATE_APPLICATION
    creator_guard = "require_absent"
    violation_cls = UnprotectedUpdatableViolation
