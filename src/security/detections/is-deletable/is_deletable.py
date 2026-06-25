"""sec-guide/is-deletable: app can reach approval with OnCompletion=DeleteApplication.

One finding per approval exit not guarded against ``OnCompletion == 5``.
Deliberately over-conservative: guards expressed via ``match`` / ``switch``
dispatch tables aren't recognised; explicit ``OnCompletion == K`` (or
``!=``) checks that control the path to the exit are.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram
from security import common


@dataclass
class IsDeletableViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application is deletable at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line}: "
            "OnCompletion == DeleteApplication can reach approval without a guard."
        )

    def __repr__(self) -> str:
        return f"IsDeletableViolation({self.pretty()})"


class IsDeletableDetector:
    name = "sec-guide/is-deletable"
    applies_to = frozenset({"app"})  # OnCompletion / app lifecycle
    # A PROPERTY, not a vulnerability: a deletable app is usually deletable on
    # purpose (the creator can tear it down). Whether *anyone* can delete it
    # without authorization is the real bug — that's unprotected-deletable.
    severity = "informational"

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

    def detect(self) -> list[IsDeletableViolation]:
        out: list[IsDeletableViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_DELETE_APPLICATION,
            ):
                out.append(IsDeletableViolation(exit_bb))
        return out
