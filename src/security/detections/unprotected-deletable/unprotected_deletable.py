"""sec-guide/unprotected-deletable: deletable AND no sender==creator guard.

Mirrors ``unprotectedDeletable.ql``. Approval exit reachable with
``OnCompletion == DeleteApplication`` AND no dominating ``txn Sender ==
global CreatorAddress`` check — anyone can delete the application.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram
from tealtools.detections import common


@dataclass
class UnprotectedDeletableViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application is deletable by anyone at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line}: "
            "no sender == creator check guards the approval path for DeleteApplication."
        )

    def __repr__(self) -> str:
        return f"UnprotectedDeletableViolation({self.pretty()})"


class UnprotectedDeletableDetector:
    name = "sec-guide/unprotected-deletable"
    applies_to = frozenset({"app"})  # OnCompletion / app lifecycle

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

    def detect(self) -> list[UnprotectedDeletableViolation]:
        out: list[UnprotectedDeletableViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_DELETE_APPLICATION,
            ):
                continue
            if common.sender_creator_guard_dominates(self.prog, self.pp, exit_bb):
                continue
            out.append(UnprotectedDeletableViolation(exit_bb))
        return out
