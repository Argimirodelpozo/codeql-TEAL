"""Attacker-controlled inner-transaction fund flow on lifted pre-IR."""
from __future__ import annotations

from tealql.tealtools.language.avm import FUND_FIELDS

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class TaintedFundFlowViolation(_LiftedTaintSinkViolation):
    pass


class TaintedFundFlowDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-fund-flow"
    violation_cls = TaintedFundFlowViolation
    fields = FUND_FIELDS

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        return (
            f"[{finding.severity}] attacker-controlled itxn {finding.field} <- "
            f"{sources} ({location}, {finding.sub_id}); no dominating check of "
            "the value or txn Sender (lifted interprocedural)"
        )
