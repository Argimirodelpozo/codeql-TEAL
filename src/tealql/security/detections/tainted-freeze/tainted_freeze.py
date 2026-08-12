"""Attacker-controlled inner asset-freeze target on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class TaintedFreezeViolation(_LiftedTaintSinkViolation):
    pass


class TaintedFreezeDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-freeze"
    violation_cls = TaintedFreezeViolation
    fields = {"FreezeAssetAccount": "HIGH", "FreezeAsset": "MEDIUM"}

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        effect = (
            "freeze any account it names"
            if finding.field == "FreezeAssetAccount"
            else "target any asset it can freeze"
        )
        return (
            f"[{finding.severity}] attacker-controlled asset-freeze target itxn "
            f"{finding.field} <- {sources} ({location}, {finding.sub_id}); the "
            f"contract will {effect} — no dominating check of the value or txn "
            "Sender (lifted interprocedural)"
        )

