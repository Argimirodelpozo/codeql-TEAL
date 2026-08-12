"""Attacker-controlled persistent-state destination on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)

_STATE_KIND = {
    "app_global_put": "global",
    "app_local_put": "local",
    "box_put": "box",
    "box_create": "box",
    "box_replace": "box",
}


class TaintedStateWriteViolation(_LiftedTaintSinkViolation):
    pass


class TaintedStateWriteDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/tainted-state-write"
    violation_cls = TaintedStateWriteViolation

    def _raw_findings(self, lifter):
        from tealql.tealtools.lift import fund_flow
        return fund_flow.tainted_state_writes(
            lifter, trusted_args=self.trusted_args,
        )

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        kind = _STATE_KIND.get(finding.field, "state")
        return (
            f"[{finding.severity}] attacker-controlled {kind}-state write KEY "
            f"in {finding.field} <- {sources} ({location}, {finding.sub_id}); "
            f"the attacker chooses the destination slot and can overwrite owner "
            f"or admin {kind} state — no dominating check of the key or txn "
            "Sender (lifted interprocedural)"
        )

