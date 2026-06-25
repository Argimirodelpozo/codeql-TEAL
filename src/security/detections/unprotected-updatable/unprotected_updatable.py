"""sec-guide/unprotected-updatable: updatable AND no sender==creator guard.

Approval exit reachable with
``OnCompletion == UpdateApplication`` AND no dominating ``txn Sender ==
global CreatorAddress`` check — anyone can update the contract code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram
from security import common


@dataclass
class UnprotectedUpdatableViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application is updatable by anyone at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line}: "
            "no sender == creator check guards the approval path for UpdateApplication."
        )

    def __repr__(self) -> str:
        return f"UnprotectedUpdatableViolation({self.pretty()})"


class UnprotectedUpdatableDetector:
    name = "sec-guide/unprotected-updatable"
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
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list[UnprotectedUpdatableViolation]:
        out: list[UnprotectedUpdatableViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_UPDATE_APPLICATION,
            ):
                continue
            if common.sender_creator_guard_dominates(self.prog, self.pp, exit_bb):
                continue
            out.append(UnprotectedUpdatableViolation(exit_bb))
        return out
