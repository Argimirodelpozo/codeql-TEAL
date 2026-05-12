"""sec-guide/group-size-check: gtxn used without GroupSize validation.

Mirrors ``groupSizeCheck.ql``. Per-``gtxn`` finding when the program
uses any absolute-index ``gtxn`` op AND doesn't validate ``global
GroupSize`` anywhere. An attacker could pad the group with extra
transactions otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import Assignment, SSAProgram
from . import common


_GTXN_OPS = frozenset({"gtxn", "gtxna", "gtxnas"})


@dataclass
class GroupSizeCheckViolation:
    gtxn_op: Assignment

    def pretty(self) -> str:
        return (
            f"{self.gtxn_op.op}@{common.loc(self.gtxn_op)}  "
            "gtxn access uses an absolute group index without validating global "
            "GroupSize — attackers can pad the group with extra transactions."
        )

    def __repr__(self) -> str:
        return f"GroupSizeCheckViolation({self.pretty()})"


class GroupSizeCheckDetector:
    name = "sec-guide/group-size-check"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[GroupSizeCheckViolation]:
        if common.has_groupsize_check(self.prog, file=self.file):
            return []
        return [
            GroupSizeCheckViolation(gtxn_op=a)
            for a in self.prog.assignments
            if a.op in _GTXN_OPS
            and common._file_match(a.location.file, self.file)
        ]
