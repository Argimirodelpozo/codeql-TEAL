"""sec-guide/ir-tainted-state-write: attacker-controlled state-write KEY (IR).

A user-input-tainted value reaching the KEY (the destination slot) of a persistent
state write -- ``app_global_put`` / ``app_local_put`` / ``box_put`` /
``box_create`` / ``box_replace`` -- lets the attacker write to a slot they choose:
overwrite the contract's own owner / admin / accounting GLOBAL state, or collide
with a sensitive box. Only the KEY is flagged, not the VALUE (storing user data is
normal). A new sink CATEGORY (the first IR detector on a non-itxn sink); lift-only.
Low-FP by construction: a key from ``txn Sender`` (the ``box[Sender]`` per-caller
pattern) is not a taint source, and a key checked against state is guard-cleared.
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
