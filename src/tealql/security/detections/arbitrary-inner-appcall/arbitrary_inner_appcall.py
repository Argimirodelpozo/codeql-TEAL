"""Attacker-controlled inner application target, evaluated on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class ArbitraryInnerAppcallViolation(_LiftedTaintSinkViolation):
    pass


class ArbitraryInnerAppcallDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/arbitrary-inner-appcall"
    violation_cls = ArbitraryInnerAppcallViolation
    fields = {"ApplicationID": "HIGH"}

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        return (
            f"[{finding.severity}] attacker-controlled inner-app-call target "
            f"itxn {finding.field} <- {sources} ({location}, {finding.sub_id}); "
            "the contract will call any application the attacker names — no "
            "dominating check of the target or txn Sender (lifted interprocedural)"
        )
