"""sec-guide/is-updatable: app can reach approval with OnCompletion=UpdateApplication.

Mirrors ``isUpdatable.ql``. One finding per approval exit not guarded
against ``OnCompletion == 4``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..path_predicates import PathPredicateAnalysis
from ..ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class IsUpdatableViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application is updatable at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line}: "
            "OnCompletion == UpdateApplication can reach approval without a guard."
        )

    def __repr__(self) -> str:
        return f"IsUpdatableViolation({self.pretty()})"


class IsUpdatableDetector:
    name = "sec-guide/is-updatable"

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

    def detect(self) -> list[IsUpdatableViolation]:
        out: list[IsUpdatableViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_UPDATE_APPLICATION,
            ):
                out.append(IsUpdatableViolation(exit_bb))
        return out
