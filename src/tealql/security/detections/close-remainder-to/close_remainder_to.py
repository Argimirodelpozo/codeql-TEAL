"""sec-guide/close-remainder-to: an approval exit reachable without crossing an
ENFORCED comparison of ``txn CloseRemainderTo``. Accepts per-branch / replicated
checks, and follows the field through phi / scratch / proto-frame.
"""
from __future__ import annotations


from tealql.security._approval_exit import _ApprovalExitViolation, _ApprovalExitProtectedDetector


class CloseRemainderToViolation(_ApprovalExitViolation):
    message = ("is reachable without a CloseRemainderTo check — the account's entire ALGO balance can be drained.")


class CloseRemainderToDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/close-remainder-to"
    field = "CloseRemainderTo"
    # CloseRemainderTo empties the SIGNER's account on a payment txn, and an
    # appl txn has no such field — a delegated-logicsig concern.
    applies_to = frozenset({"logicsig"})
    signed_txn = True   # only the SIGNED txn's own field protects the signer
    violation_cls = CloseRemainderToViolation
