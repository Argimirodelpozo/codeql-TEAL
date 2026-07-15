"""sec-guide/rekey-to: path-aware missing-RekeyTo detector.

For each approval exit, checks that
every CFG path from any program entry to the exit crosses at least one
BB containing a comparison receiving flow from ``txn RekeyTo`` whose
result reaches enforcement (``assert`` / ``bnz`` to ``err`` / ``bz`` to
``err``). Per-exit alerts — partially-guarded contracts produce one
alert per unprotected exit.
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
        # Structured anchor for machine output (JSON/SARIF/suppressions);
        # mirrors pretty(): the exit's LAST line.
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
    # Signed-txn-field check: RekeyTo on the outer txn rekeys the SIGNER's
    # account — a delegated-logicsig concern; on an app it is the caller's
    # own signed txn (see common.py doctrine; rekey was removed from the
    # app fund-flow fields for the same reason).
    applies_to = frozenset({"logicsig"})
    signed_txn = True   # only the SIGNED txn's own field protects the signer
    violation_cls = RekeyToViolation
