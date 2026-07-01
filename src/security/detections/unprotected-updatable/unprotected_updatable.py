"""sec-guide/unprotected-updatable: updatable AND no sender==creator guard.

Approval exit reachable with
``OnCompletion == UpdateApplication`` AND no dominating ``txn Sender ==
global CreatorAddress`` check — anyone can update the contract code.
"""
from __future__ import annotations

from security import common
from security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


class UnprotectedUpdatableViolation(_ExitBBViolation):
    headline = "Application is updatable by anyone"
    detail = "no sender == creator check guards the approval path for UpdateApplication."


class UnprotectedUpdatableDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/unprotected-updatable"
    action = common.ONC_UPDATE_APPLICATION
    creator_guard = "require_absent"
    violation_cls = UnprotectedUpdatableViolation
