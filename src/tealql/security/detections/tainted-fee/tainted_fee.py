"""Attacker-controlled inner-transaction fee on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class TaintedFeeViolation(_LiftedTaintSinkViolation):
    pass


class TaintedFeeDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-fee"
    violation_cls = TaintedFeeViolation
    fields = {"Fee": "MEDIUM"}

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        return (
            f"[{finding.severity}] attacker-controlled inner-txn fee itxn "
            f"{finding.field} <- {sources} ({location}, {finding.sub_id}); the "
            "attacker sets the fee the app pays and can drain its balance via "
            "inflated fees — no dominating check of the value "
            "(lifted interprocedural)"
        )

