"""sec-guide/inner-txn-close-rekey: any ``itxn_field`` writing CloseRemainderTo /
RekeyTo / AssetCloseTo, which should be left at their zero-address default.

A write whose value PROVABLY resolves to the zero address is suppressed — that is
a defensive no-op equal to the default, and compilers emit it routinely.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import Assignment, SSAProgram
from tealql.security import common
from tealql.tealtools.avm import CLOSE_REKEY_FIELDS as _DANGEROUS_FIELDS


@dataclass
class InnerTxnCloseRekeyViolation:
    assignment: Assignment
    field: str

    @property
    def file(self) -> str:
        return self.assignment.location.file

    @property
    def line(self) -> int:
        # Must mirror pretty().
        return self.assignment.location.line

    def pretty(self) -> str:
        return (
            f"itxn_field {self.field}@{common.loc(self.assignment)}  "
            f"Inner transaction sets {self.field} — this can drain the application "
            "account or transfer signing authority. Omit this field entirely."
        )

    def __repr__(self) -> str:
        return f"InnerTxnCloseRekeyViolation({self.pretty()})"


class InnerTxnCloseRekeyDetector:
    severity = "high"
    name = "sec-guide/inner-txn-close-rekey"
    applies_to = frozenset({"app"})  # itxn_* is app-only

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        # Const propagation is what resolves a 32-zero-byte literal for the
        # safe-no-op suppression; idempotent, so only a direct-use fallback.
        common.prepare(prog)
        self.prog = prog
        self.file = file

    def detect(self) -> list[InnerTxnCloseRekeyViolation]:
        out: list[InnerTxnCloseRekeyViolation] = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field not in _DANGEROUS_FIELDS:
                continue
            if common.value_is_zero_address(self.prog, fs.value, file=self.file):
                continue                       # zeroing the field == its default
            out.append(InnerTxnCloseRekeyViolation(
                assignment=fs.assignment, field=fs.field,
            ))
        return out
