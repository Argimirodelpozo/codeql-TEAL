"""sec-guide/lease-validation: an approval exit reachable without ``txn Lease``
being compared and the comparison gating approval (polarity-agnostic).

A delegated LogicSig signs the SHAPE of a transaction, not an instance, so
without a non-zero Lease making (Sender, Lease) single-use the same signed
transaction can be replayed until the delegating key rotates. Narrowed to
logicsigs: an app has state-based replay protection, so flagging it there is a
false positive.
"""
from __future__ import annotations

from dataclasses import dataclass

from tealql.tealtools.ssa import BasicBlock
from tealql.security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class LeaseValidationViolation:
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
            "is reachable without a Lease check — a delegated LogicSig that "
            "doesn't pin txn Lease can have its signed transaction replayed."
        )

    def __repr__(self) -> str:
        return f"LeaseValidationViolation({self.pretty()})"


class LeaseValidationDetector(_ApprovalExitProtectedDetector):
    name = "sec-guide/lease-validation"
    applies_to = frozenset({"logicsig"})  # apps have state-based replay protection
    field = "Lease"
    # A lease is scoped to (Sender, Lease) of the txn carrying it, so only the
    # SIGNED txn's own Lease gives this LogicSig replay protection.
    signed_txn = True
    violation_cls = LeaseValidationViolation
