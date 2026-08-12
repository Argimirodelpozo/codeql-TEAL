"""sec-guide/tx-type-check: an approval exit reachable without crossing an ENFORCED
comparison of EITHER ``txn TypeEnum`` or ``txn Type`` — validating either one
counts as restricting the transaction type.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import BasicBlock, SSAProgram
from tealql.security._field_protection import approval_exit_protected_for_any_txn_field
from tealql.security._program_shape import approving_exits


@dataclass
class TxTypeCheckViolation:
    exit_bb: BasicBlock

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Must mirror pretty(): the exit's LAST line.
        return self.exit_bb.last_line

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a txn Type / TypeEnum check — "
            "any transaction type is accepted."
        )

    def __repr__(self) -> str:
        return f"TxTypeCheckViolation({self.pretty()})"


class TxTypeCheckDetector:
    severity = "high"
    name = "sec-guide/tx-type-check"
    # An application is ALWAYS invoked as an `appl` txn, so checking its own
    # TypeEnum is redundant and flagging its absence is a false positive.
    # Validating a SIBLING's type is the unvalidated-group-sibling concern.
    applies_to = frozenset({"logicsig"})

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[TxTypeCheckViolation]:
        out: list[TxTypeCheckViolation] = []
        for exit_bb in sorted(
            approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not approval_exit_protected_for_any_txn_field(
                self.prog, exit_bb, ["TypeEnum", "Type"], file=self.file,
            ):
                out.append(TxTypeCheckViolation(exit_bb))
        return out
