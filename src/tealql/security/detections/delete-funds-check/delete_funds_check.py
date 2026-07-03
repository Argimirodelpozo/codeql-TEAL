"""sec-guide/delete-funds-check: DeleteApplication without balance==min_balance check.

Flags an approval exit reachable with ``OnCompletion == DeleteApplication`` when
the program has no genuine balance-vs-min-balance check — the canonical "are funds
drained?" guard before a delete.

The funds-check recognition *ties the two opcodes together*: a ``balance`` value
and a ``min_balance`` value must flow (through the phi / scratch / proto-frame
bridge) into the SAME comparison or subtraction (``balance == min_balance``,
``balance <= min_balance``, ``balance - min_balance`` …). The old proxy only asked
whether both opcodes appeared *anywhere* in the program, so two unrelated uses
(e.g. ``min_balance`` of one account, ``balance`` of another, never compared)
silently suppressed the finding — a false negative.
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
    """A genuine funds check: a ``balance`` value and a ``min_balance`` value flow
    into the same comparison / subtraction (one on each side). Stronger than the
    old "both opcodes appear somewhere" presence proxy."""
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

    # The tie must be ENFORCED — a `balance == min_balance` (or
    # `balance - min_balance`) whose result is dropped (`pop`) or sits on an
    # unrelated branch is no funds check. Without this an attacker silences the
    # detector with one dead comparison while leaving Delete unprotected.
    return common.enforced_op_exists(prog, _TIE_OPS, _tied, file=file)


class DeleteFundsCheckDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/delete-funds-check"
    action = common.ONC_DELETE_APPLICATION
    violation_cls = DeleteFundsCheckViolation

    def applies(self) -> bool:
        return not _has_balance_minbalance_check(self.prog, self.file)
