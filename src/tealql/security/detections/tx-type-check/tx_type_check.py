"""sec-guide/tx-type-check: an approval exit reachable without crossing an ENFORCED
comparison of EITHER ``txn TypeEnum`` or ``txn Type`` — validating either one
counts as restricting the transaction type.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.security._approval_exit import _ApprovalExitViolation
from tealql.security._field_protection import approval_exit_protected_for_any_txn_field
from tealql.security._program_shape import approving_exits


class TxTypeCheckViolation(_ApprovalExitViolation):
    message = ('is reachable without a txn Type / TypeEnum check — any transaction type is accepted.')


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
