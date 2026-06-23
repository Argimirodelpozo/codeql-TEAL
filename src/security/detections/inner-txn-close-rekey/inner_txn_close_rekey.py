"""sec-guide/inner-txn-close-rekey: itxn sets CloseRemainderTo / RekeyTo / AssetCloseTo.

Per-assignment finding for any
``itxn_field`` writing one of the dangerous fields — these should
typically default to the zero address, not be set explicitly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import Assignment, SSAProgram
from security import common
from tealtools.opsets import CLOSE_REKEY_FIELDS as _DANGEROUS_FIELDS


@dataclass
class InnerTxnCloseRekeyViolation:
    assignment: Assignment
    field: str

    def pretty(self) -> str:
        return (
            f"itxn_field {self.field}@{common.loc(self.assignment)}  "
            f"Inner transaction sets {self.field} — this can drain the application "
            "account or transfer signing authority. Omit this field entirely."
        )

    def __repr__(self) -> str:
        return f"InnerTxnCloseRekeyViolation({self.pretty()})"


class InnerTxnCloseRekeyDetector:
    name = "sec-guide/inner-txn-close-rekey"
    applies_to = frozenset({"app"})  # itxn_* is app-only

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[InnerTxnCloseRekeyViolation]:
        out: list[InnerTxnCloseRekeyViolation] = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field in _DANGEROUS_FIELDS:
                out.append(InnerTxnCloseRekeyViolation(
                    assignment=fs.assignment, field=fs.field,
                ))
        return out
