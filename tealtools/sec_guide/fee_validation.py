"""sec-guide/fee-validation: missing Fee check.

Mirrors ``feeValidation.ql``. Flags a contract that doesn't compare
``txn Fee`` against any value — attackers can drain the account through
inflated fees.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import SSAProgram
from . import common


@dataclass
class FeeValidationViolation:
    prog: SSAProgram

    def pretty(self) -> str:
        return (
            "Contract does not validate txn Fee "
            "— an attacker can set excessively high fees to drain the account."
        )

    def __repr__(self) -> str:
        return f"FeeValidationViolation({self.pretty()})"


class FeeValidationDetector:
    name = "sec-guide/fee-validation"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[FeeValidationViolation]:
        if common.has_fee_check(self.prog, file=self.file):
            return []
        return [FeeValidationViolation(self.prog)]
