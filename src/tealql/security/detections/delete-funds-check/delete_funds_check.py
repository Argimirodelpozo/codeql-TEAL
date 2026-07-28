"""sec-guide/delete-funds-check: an approval exit reachable with ``OnCompletion ==
DeleteApplication`` in a program with no genuine balance-vs-min-balance check, the
canonical "are the funds out?" guard before a delete.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.security import common
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


_TIE_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "-",
    "b==", "b!=", "b<", "b>", "b<=", "b>=", "b-",
})


class DeleteFundsCheckViolation(_ExitBBViolation):
    headline = "Application handles DeleteApplication"
    joiner = " without checking balance == min_balance — "
    detail = "funds may be locked permanently on deletion."


def _has_balance_minbalance_check(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    """A genuine funds check: ``balance`` and ``min_balance`` values flow into the
    SAME comparison or subtraction, one on each side.

    HAZARD: opcode presence is not enough. Two unrelated uses — ``min_balance`` of
    one account, ``balance`` of another, never compared — would suppress the
    finding on a contract with no funds check at all."""
    bal = common.op_output_seeds(prog, "balance", file=file)
    mb = common.op_output_seeds(prog, "min_balance", file=file)
    if not bal or not mb:
        return False

    def _tied(op) -> bool:
        # balance on one side, min_balance on the other (either order).
        if len(op.inputs) != 2:
            return False
        x, y = op.inputs
        return (
            (common._operand_flows_from_field_var(prog, x, bal)
                and common._operand_flows_from_field_var(prog, y, mb))
            or
            (common._operand_flows_from_field_var(prog, y, bal)
                and common._operand_flows_from_field_var(prog, x, mb))
        )

    # And ENFORCED: a tie whose result is dropped (`pop`) or sits on an unrelated
    # branch is no funds check, so one dead comparison would silence the detector.
    return common.enforced_op_exists(prog, _TIE_OPS, _tied, file=file)


class DeleteFundsCheckDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/delete-funds-check"
    action = common.ONC_DELETE_APPLICATION
    violation_cls = DeleteFundsCheckViolation

    def applies(self) -> bool:
        return not _has_balance_minbalance_check(self.prog, self.file)
