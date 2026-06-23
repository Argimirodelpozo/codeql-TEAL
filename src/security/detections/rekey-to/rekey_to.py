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

from tealtools.ssa import BasicBlock
from security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class RekeyToViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a RekeyTo check — an attacker can rekey the account."
        )

    def __repr__(self) -> str:
        return f"RekeyToViolation({self.pretty()})"


class RekeyToDetector(_ApprovalExitProtectedDetector):
    name = "sec-guide/rekey-to"
    field = "RekeyTo"
    violation_cls = RekeyToViolation
