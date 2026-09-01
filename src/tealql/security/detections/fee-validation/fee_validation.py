"""sec-guide/fee-validation: an approval exit reachable without crossing an
ENFORCED comparison of ``txn Fee`` — an attacker drains the account via the fee.
"""
from __future__ import annotations


from tealql.security._approval_exit import _ApprovalExitViolation, _ApprovalExitProtectedDetector


class FeeValidationViolation(_ApprovalExitViolation):
    message = ('is reachable without a txn Fee check — an attacker can drain the account.')


class FeeValidationDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/fee-validation"
    field = "Fee"
    # An unpinned Fee drains the SIGNER via a huge fee, and only a delegated
    # logicsig approves someone else's constructed txn.
    applies_to = frozenset({"logicsig"})
    # The check must read the SIGNED txn's OWN Fee, which also credits the
    # dynamic-self `gtxns Fee` and the pinned `gtxn N Fee` forms; an unpinned
    # sibling `gtxn N` still does not count.
    signed_txn = True
    violation_cls = FeeValidationViolation
