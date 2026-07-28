"""sec-guide/inner-txn-fee: an ``itxn_field Fee`` set to a KNOWN non-zero integer
constant; dynamic fees are not flagged.
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
        # Must mirror pretty().
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
        # Needs const_value on the value SSAVar; idempotent, so this is only the
        # fallback for a detector built directly by a library caller.
        common.prepare(prog)
        self.prog = prog
        self.file = file

    def detect(self) -> list[InnerTxnFeeViolation]:
        out: list[InnerTxnFeeViolation] = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if common.inner_txn_sets_nonzero_fee(fs):
                out.append(InnerTxnFeeViolation(assignment=fs.assignment))
        return out
