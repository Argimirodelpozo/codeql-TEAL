"""sec-guide/ir-tainted-state-write: a user-input-tainted value reaching the KEY of
a persistent state write lets the attacker choose the destination slot —
overwriting owner/admin/accounting global state, or colliding with a sensitive box.

Only the KEY is flagged, never the VALUE: storing user data is normal. Low-FP by
construction — a key from ``txn Sender`` (the ``box[Sender]`` per-caller pattern)
is not a taint source, and a key checked against state is guard-cleared.
Lift-only; no SSA sibling.
"""
from __future__ import annotations

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation

_STATE = {
    "app_global_put": "global", "app_local_put": "local",
    "box_put": "box", "box_create": "box", "box_replace": "box",
}


class IrTaintedStateWriteViolation(_IrTaintSinkViolation):
    pass


class IrTaintedStateWriteDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-state-write"
    violation_cls = IrTaintedStateWriteViolation

    def _raw_findings(self, lifter):
        from tealql.tealtools.lift import fund_flow as FF
        return FF.tainted_state_writes(lifter, trusted_args=self.trusted_args)

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        kind = _STATE.get(f.field, "state")
        return (f"[{f.severity}] attacker-controlled {kind}-state write KEY in "
                f"{f.field} <- {src} ({location}, {f.sub_id}); the attacker chooses "
                f"the destination slot — can overwrite owner/admin {kind} state — "
                f"with no dominating check of the key or txn Sender (IR interprocedural)")
