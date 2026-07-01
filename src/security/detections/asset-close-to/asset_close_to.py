"""sec-guide/asset-close-to: missing AssetCloseTo validation.

Strict-dominance form: a single comparison must dominate every approval
exit.
"""
from __future__ import annotations

from security._field_validated import _FieldValidatedDetector, _FieldValidatedViolation


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
