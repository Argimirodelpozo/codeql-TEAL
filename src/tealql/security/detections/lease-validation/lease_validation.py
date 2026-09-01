"""sec-guide/lease-validation: an approval exit reachable without ``txn Lease``
being compared and the comparison gating approval (polarity-agnostic).

A delegated LogicSig signs the SHAPE of a transaction, not an instance, so
without a non-zero Lease making (Sender, Lease) single-use the same signed
transaction can be replayed until the delegating key rotates. Narrowed to
logicsigs: an app has state-based replay protection, so flagging it there is a
false positive.
"""
from __future__ import annotations


from tealql.security._approval_exit import _ApprovalExitViolation, _ApprovalExitProtectedDetector


class LeaseValidationViolation(_ApprovalExitViolation):
    message = ("is reachable without a Lease check — a delegated LogicSig that doesn't pin txn Lease can have its signed transaction replayed.")


class LeaseValidationDetector(_ApprovalExitProtectedDetector):
    name = "sec-guide/lease-validation"
    applies_to = frozenset({"logicsig"})  # apps have state-based replay protection
    field = "Lease"
    # A lease is scoped to (Sender, Lease) of the txn carrying it, so only the
    # SIGNED txn's own Lease gives this LogicSig replay protection.
    signed_txn = True
    violation_cls = LeaseValidationViolation
