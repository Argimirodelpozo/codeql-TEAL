"""sec-guide/rekey-to: an approval exit reachable without crossing an ENFORCED
comparison of ``txn RekeyTo``. One alert per unprotected exit, so a
partially-guarded contract reports each gap.
"""
from __future__ import annotations


from tealql.security._approval_exit import _ApprovalExitViolation, _ApprovalExitProtectedDetector


class RekeyToViolation(_ApprovalExitViolation):
    message = ('is reachable without a RekeyTo check — an attacker can rekey the account.')


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
