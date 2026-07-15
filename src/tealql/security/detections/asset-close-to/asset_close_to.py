"""sec-guide/asset-close-to: missing AssetCloseTo validation.

Every-path form: ``AssetCloseTo`` must be ENFORCED (asserted / branch-to-reject)
on every approving path — a must-reach on the enforcement site, not merely a
comparison that dominates the exits (see :func:`common.field_validated_on_all_paths`).
"""
from __future__ import annotations

from tealql.security._field_validated import _FieldValidatedDetector, _FieldValidatedViolation


class AssetCloseToViolation(_FieldValidatedViolation):
    pass


class AssetCloseToDetector(_FieldValidatedDetector):
    severity = "high"
    name = "sec-guide/asset-close-to"
    field = ("AssetCloseTo",)
    # Signed-txn-field check: AssetCloseTo drains the SIGNER's asset holding
    # on an axfer — delegated-logicsig concern.
    applies_to = frozenset({"logicsig"})
    message = (
        "Contract does not validate txn AssetCloseTo "
        "— all asset units can be drained from the account."
    )
    violation_cls = AssetCloseToViolation
