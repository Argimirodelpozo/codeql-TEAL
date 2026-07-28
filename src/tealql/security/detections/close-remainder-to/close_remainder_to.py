"""sec-guide/close-remainder-to: an approval exit reachable without crossing an
ENFORCED comparison of ``txn CloseRemainderTo``. Accepts per-branch / replicated
checks, and follows the field through phi / scratch / proto-frame.
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
        # Must mirror pretty(): the exit's LAST line.
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
    # CloseRemainderTo empties the SIGNER's account on a payment txn, and an
    # appl txn has no such field — a delegated-logicsig concern.
    applies_to = frozenset({"logicsig"})
    signed_txn = True   # only the SIGNED txn's own field protects the signer
    violation_cls = CloseRemainderToViolation
