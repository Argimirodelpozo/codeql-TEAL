"""Attacker-controlled inner asset administration roles on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)

_ROLE = {
    "ConfigAssetManager": "reconfigure or destroy the asset",
    "ConfigAssetClawback": "claw back any holder's units",
    "ConfigAssetFreeze": "freeze any holder",
    "ConfigAssetReserve": "control the reserve",
}


class TaintedAssetAdminViolation(_LiftedTaintSinkViolation):
    pass


class TaintedAssetAdminDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-asset-admin"
    violation_cls = TaintedAssetAdminViolation
    fields = {
        "ConfigAssetManager": "CRITICAL",
        "ConfigAssetClawback": "CRITICAL",
        "ConfigAssetFreeze": "HIGH",
        "ConfigAssetReserve": "MEDIUM",
    }

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        role = _ROLE.get(finding.field, "administer the asset")
        return (
            f"[{finding.severity}] attacker-controlled asset-admin role itxn "
            f"{finding.field} <- {sources} ({location}, {finding.sub_id}); the "
            f"attacker can install themselves as the address that can {role} — "
            "no dominating check of the value or txn Sender "
            "(lifted interprocedural)"
        )

