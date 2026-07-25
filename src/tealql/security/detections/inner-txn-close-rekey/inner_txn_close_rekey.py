"""sec-guide/inner-txn-close-rekey: itxn sets CloseRemainderTo / RekeyTo / AssetCloseTo.

Per-assignment finding for any ``itxn_field`` writing one of the dangerous fields
— these should typically default to the zero address, not be set explicitly.

A write whose value *provably resolves to the zero address*
(:func:`common.value_is_zero_address` — a 32-zero-byte constant or a value flowing
from ``global ZeroAddress`` through phi / scratch / proto-frame) is suppressed: it
is a defensive no-op equal to the field's default, not the drain/rekey
antipattern. Without this, compilers that explicitly zero RekeyTo/CloseRemainderTo
(a common safe idiom) tripped a false positive.
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
        # Structured anchor for machine output; mirrors pretty().
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
        # Const propagation lets a 32-zero-byte literal / scratch-loaded
        # ZeroAddress resolve for the safe-no-op suppression below. Idempotent
        # fallback — the runner prepares the program once.
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
