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

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram, SSAVar
from security import common


@dataclass
class DeleteFundsCheckViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application handles DeleteApplication at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line} without checking balance == min_balance "
            "— funds may be locked permanently on deletion."
        )

    def __repr__(self) -> str:
        return f"DeleteFundsCheckViolation({self.pretty()})"


_TIE_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "-",
    "b==", "b!=", "b<", "b>", "b<=", "b>=", "b-",
})


def _seeds(prog: SSAProgram, op: str, file: Optional[str]) -> set:
    return {
        o for a in prog.assignments
        if a.op == op and common.file_match(a.location.file, file)
        for o in a.outputs if isinstance(o, SSAVar)
    }


def _has_balance_minbalance_check(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    """A genuine funds check: a ``balance`` value and a ``min_balance`` value flow
    into the same comparison / subtraction (one on each side). Stronger than the
    old "both opcodes appear somewhere" presence proxy."""
    bal = _seeds(prog, "balance", file)
    mb = _seeds(prog, "min_balance", file)
    if not bal or not mb:
        return False
    for op in prog.assignments:
        if op.op not in _TIE_OPS or len(op.inputs) != 2:
            continue
        if not common.file_match(op.location.file, file):
            continue
        x, y = op.inputs
        if (common._operand_flows_from_field_var(prog, x, bal)
                and common._operand_flows_from_field_var(prog, y, mb)) or \
           (common._operand_flows_from_field_var(prog, y, bal)
                and common._operand_flows_from_field_var(prog, x, mb)):
            return True
    return False


class DeleteFundsCheckDetector:
    name = "sec-guide/delete-funds-check"
    applies_to = frozenset({"app"})  # DeleteApplication / balance / min_balance

    def __init__(
        self,
        prog: SSAProgram,
        *,
        path_predicates: Optional[PathPredicateAnalysis] = None,
        file: Optional[str] = None,
    ):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or PathPredicateAnalysis(prog)

    def detect(self) -> list[DeleteFundsCheckViolation]:
        if _has_balance_minbalance_check(self.prog, self.file):
            return []
        out: list[DeleteFundsCheckViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_DELETE_APPLICATION,
            ):
                out.append(DeleteFundsCheckViolation(exit_bb))
        return out
