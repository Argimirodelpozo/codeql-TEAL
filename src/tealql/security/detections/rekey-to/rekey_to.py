"""sec-guide/rekey-to: an approval exit reachable without crossing an ENFORCED
comparison of ``txn RekeyTo``. One alert per unprotected exit, so a
partially-guarded contract reports each gap.
"""
from __future__ import annotations

from dataclasses import dataclass

from tealql.tealtools.ssa import BasicBlock
from tealql.security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class RekeyToViolation:
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
            "is reachable without a RekeyTo check — an attacker can rekey the account."
        )

    def __repr__(self) -> str:
        return f"RekeyToViolation({self.pretty()})"


class RekeyToDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/rekey-to"
    field = "RekeyTo"
    # RekeyTo on the outer txn rekeys the SIGNER's account, so this is a
    # delegated-logicsig concern; on an app it is the CALLER's own signed txn,
    # which is why rekey was removed from the app fund-flow fields too.
    applies_to = frozenset({"logicsig"})
    signed_txn = True   # only the SIGNED txn's own field protects the signer
    violation_cls = RekeyToViolation
