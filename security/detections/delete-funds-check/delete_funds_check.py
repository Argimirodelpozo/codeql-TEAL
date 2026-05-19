"""sec-guide/delete-funds-check: DeleteApplication without balance==min_balance check.

Mirrors ``deleteFundsCheck.ql``. Flags an approval exit reachable with
``OnCompletion == DeleteApplication`` when the program also lacks any
use of both ``balance`` and ``min_balance`` opcodes — a balance vs.
min-balance comparison is the canonical "are funds drained?" check
before a delete. The QL form doesn't actually verify the comparison
ties them together; the bare presence of both opcodes is the proxy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram
from tealtools.detections import common


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


def _has_balance_minbalance_pair(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    has_balance = any(
        a.op == "balance" for a in prog.assignments
        if common._file_match(a.location.file, file)
    )
    has_min_balance = any(
        a.op == "min_balance" for a in prog.assignments
        if common._file_match(a.location.file, file)
    )
    return has_balance and has_min_balance


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
        if _has_balance_minbalance_pair(self.prog, self.file):
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
