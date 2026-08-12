"""Attacker-controlled event/log data on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class TaintedLogViolation(_LiftedTaintSinkViolation):
    pass


class TaintedLogDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-log"
    violation_cls = TaintedLogViolation

    def _raw_findings(self, lifter):
        from tealql.tealtools.lift import fund_flow
        return fund_flow.tainted_logs(lifter, trusted_args=self.trusted_args)

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        return (
            f"[{finding.severity}] attacker-controlled data emitted via log <- "
            f"{sources} ({location}, {finding.sub_id}); a caller reading this "
            "contract's LastLog or an off-chain indexer can be fed forged data — "
            "no dominating check of the value (lifted interprocedural)"
        )

