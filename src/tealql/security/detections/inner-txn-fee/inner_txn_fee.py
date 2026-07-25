"""sec-guide/inner-txn-fee: itxn explicitly sets non-zero Fee.

Per-assignment finding for any ``itxn_field Fee`` whose value resolves to
a known non-zero integer constant. Dynamic (non-constant) fees aren't
flagged.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import Assignment, SSAProgram
from tealql.security import common


@dataclass
class InnerTxnFeeViolation:
    assignment: Assignment

    @property
    def file(self) -> str:
        return self.assignment.location.file

    @property
    def line(self) -> int:
        # Structured anchor for machine output; mirrors pretty().
        return self.assignment.location.line

    def pretty(self) -> str:
        return (
            f"itxn_field Fee@{common.loc(self.assignment)}  "
            "Inner transaction sets a non-zero fee — repeated calls can drain "
            "the application account. Use fee 0 and rely on caller fee pooling."
        )

    def __repr__(self) -> str:
        return f"InnerTxnFeeViolation({self.pretty()})"


class InnerTxnFeeDetector:
    severity = "high"
    name = "sec-guide/inner-txn-fee"
    applies_to = frozenset({"app"})  # itxn_* is app-only

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        # Needs const_value on the value SSAVar (parsed as an int when
        # possible). The runner already prepared the program; this is the
        # idempotent fallback for a detector built directly by a caller.
        common.prepare(prog)
        self.prog = prog
        self.file = file

    def detect(self) -> list[InnerTxnFeeViolation]:
        out: list[InnerTxnFeeViolation] = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if common.inner_txn_sets_nonzero_fee(fs):
                out.append(InnerTxnFeeViolation(assignment=fs.assignment))
        return out
