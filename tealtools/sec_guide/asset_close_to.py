"""sec-guide/asset-close-to: missing AssetCloseTo validation.

Mirrors ``assetCloseTo.ql``. Strict-dominance form: a single comparison
must dominate every approval exit.
"""
from __future__ import annotations

from ._field_validated import _FieldValidatedDetector, _FieldValidatedViolation


class AssetCloseToViolation(_FieldValidatedViolation):
    pass


class AssetCloseToDetector(_FieldValidatedDetector):
    name = "sec-guide/asset-close-to"
    field = ("AssetCloseTo",)
    message = (
        "Contract does not validate txn AssetCloseTo "
        "— all asset units can be drained from the account."
    )
    violation_cls = AssetCloseToViolation
