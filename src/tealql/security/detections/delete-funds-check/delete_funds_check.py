"""sec-guide/delete-funds-check: an approval exit reachable with ``OnCompletion ==
DeleteApplication`` whose paths carry no genuine balance-vs-min-balance check, the
canonical "are the funds out?" guard before a delete.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import BasicBlock, SSAProgram, SSAVar
from tealql.security._action_guards import ONC_DELETE_APPLICATION
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)
from tealql.security._enforcement import _label_to_bb_first_line, scratch_forward_map
from tealql.security._field_protection import (
    _all_entry_paths_cross,
    _collect_field_enforcement_bbs,
)
from tealql.security._program_shape import file_match, op_output_seeds
from tealql.security._value_flow import _operand_flows_from_field_var


_TIE_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "-",
    "b==", "b!=", "b<", "b>", "b<=", "b>=", "b-",
})


class DeleteFundsCheckViolation(_ExitBBViolation):
    headline = "Application handles DeleteApplication"
    joiner = " without checking balance == min_balance — "
    detail = "funds may be locked permanently on deletion."


def _funds_check_gates(
    prog: SSAProgram, file: Optional[str] = None,
) -> set:
    """Blocks ENFORCING a genuine funds check: ``balance`` and ``min_balance``
    values flow into the SAME comparison or subtraction, one on each side, and
    that result reaches an enforcement sink. Empty when no such tie exists.

    HAZARD: opcode presence is not enough. Two unrelated uses — ``min_balance``
    of one account, ``balance`` of another, never compared — enforce nothing,
    and a tie whose result is dropped (``pop``) is no check either."""
    bal = op_output_seeds(prog, "balance", file=file)
    mb = op_output_seeds(prog, "min_balance", file=file)
    gates: set = set()
    if not bal or not mb:
        return gates

    def _tied(op) -> bool:
        # balance on one side, min_balance on the other (either order).
        if len(op.inputs) != 2:
            return False
        x, y = op.inputs
        return (
            (_operand_flows_from_field_var(prog, x, bal)
                and _operand_flows_from_field_var(prog, y, mb))
            or
            (_operand_flows_from_field_var(prog, y, bal)
                and _operand_flows_from_field_var(prog, x, mb))
        )

    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for op in prog.assignments:
        if op.op not in _TIE_OPS or not file_match(op.location.file, file):
            continue
        if not _tied(op) or not op.outputs or not isinstance(op.outputs[0], SSAVar):
            continue
        _collect_field_enforcement_bbs(
            prog, op.outputs[0], label_lines, gates, set(), scratch_fwd)
    return gates


class DeleteFundsCheckDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/delete-funds-check"
    action = ONC_DELETE_APPLICATION
    violation_cls = DeleteFundsCheckViolation

    def exit_protected(self, exit_bb: BasicBlock) -> bool:
        """Every entry path to THIS exit crosses an enforced balance/min_balance
        tie. Per-exit, not program-wide: a funds check in the NoOp arm proves
        nothing about a Delete arm that approves without one (finding 1.6, the
        delete-funds-check twin of timelock-upgrade)."""
        gates = getattr(self, "_gates_cache", None)
        if gates is None:
            gates = self._gates_cache = _funds_check_gates(self.prog, self.file)
        return bool(gates) and _all_entry_paths_cross(self.prog, exit_bb, gates)
