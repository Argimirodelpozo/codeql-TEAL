"""sec-guide/fee-validation: missing Fee check (path-aware).

Per-approval-exit: each exit must be reachable only along CFG paths
that cross a BB where ``txn Fee`` flows into a comparison whose result
reaches enforcement (``assert`` / ``bnz`` to ``err`` / ``bz`` to ``err``).
Same machinery as :mod:`security.rekey_to`.

Replaces the old whole-program existence check (``compared anywhere?``),
which produced false negatives on programs that validated ``Fee`` only
on one branch (``vuln_branch_skip``) or inside a subroutine never
called on every path (``vuln_subroutine_dead``).
"""
from __future__ import annotations

from dataclasses import dataclass

from tealtools.ssa import BasicBlock
from security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class FeeValidationViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a txn Fee check — an attacker can drain the account."
        )

    def __repr__(self) -> str:
        return f"FeeValidationViolation({self.pretty()})"


class FeeValidationDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/fee-validation"
    field = "Fee"
    # Signed-txn-field check: an unpinned Fee drains the SIGNER via a huge
    # fee — only a delegated logicsig approves someone else's constructed txn.
    applies_to = frozenset({"logicsig"})
    violation_cls = FeeValidationViolation
