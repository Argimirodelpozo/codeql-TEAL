"""sec-guide/close-remainder-to: missing CloseRemainderTo validation.

Path-aware form (migrated off the old strict-dominance base): for each approval
exit, every CFG path from a program entry to it must cross a comparison receiving
flow from ``txn CloseRemainderTo`` whose result reaches enforcement. Accepts
per-branch / replicated checks and, via the shared ``common`` field-flow bridge,
follows the field through phi / scratch / proto-frame (interprocedural). Per-exit
alerts.
"""
from __future__ import annotations

from dataclasses import dataclass

from tealql.tealtools.ssa import BasicBlock
from tealql.security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class CloseRemainderToViolation:
    exit_bb: BasicBlock

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Structured anchor for machine output (JSON/SARIF/suppressions);
        # mirrors pretty(): the exit's LAST line.
        return self.exit_bb.last_line

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a CloseRemainderTo check "
            "— the account's entire ALGO balance can be drained."
        )

    def __repr__(self) -> str:
        return f"CloseRemainderToViolation({self.pretty()})"


class CloseRemainderToDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/close-remainder-to"
    field = "CloseRemainderTo"
    # Signed-txn-field check: CloseRemainderTo empties the SIGNER's account
    # on a payment txn — delegated-logicsig concern (an appl txn has none).
    applies_to = frozenset({"logicsig"})
    signed_txn = True   # only the SIGNED txn's own field protects the signer
    violation_cls = CloseRemainderToViolation
