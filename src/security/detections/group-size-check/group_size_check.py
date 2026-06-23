"""sec-guide/group-size-check: missing GroupSize check (path-aware).

Per-approval-exit: each exit must be reachable only along CFG paths
that cross a BB where ``global GroupSize`` flows into a comparison
whose result reaches enforcement. Uses the same machinery as
:mod:`security.rekey_to`, but seeded from ``global FIELD``
reads instead of ``txn FIELD``.

Replaces the old heuristic (``compared anywhere?`` + per-``gtxn``
finding gated on whole-program presence) which produced false
negatives whenever the validation was on one branch only, or in a
subroutine never called on every path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import BasicBlock, SSAProgram
from security import common


@dataclass
class GroupSizeCheckViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a global GroupSize check — "
            "attackers can pad the group with extra transactions."
        )

    def __repr__(self) -> str:
        return f"GroupSizeCheckViolation({self.pretty()})"


class GroupSizeCheckDetector:
    name = "sec-guide/group-size-check"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[GroupSizeCheckViolation]:
        out: list[GroupSizeCheckViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_global_field(
                self.prog, exit_bb, "GroupSize", file=self.file,
            ):
                out.append(GroupSizeCheckViolation(exit_bb))
        return out
