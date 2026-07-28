"""sec-guide/ir-tainted-fee: a user-input-tainted ``itxn_field Fee`` lets the
attacker set the fee the app pays and drain its balance one inflated inner txn at
a time. Covers exactly the dynamic case ``inner-txn-fee`` skips (that one flags a
CONSTANT non-zero fee). Lift-only; no SSA sibling.
"""
from __future__ import annotations

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrTaintedFeeViolation(_IrTaintSinkViolation):
    pass


class IrTaintedFeeDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-fee"
    violation_cls = IrTaintedFeeViolation
    fields = {"Fee": "MEDIUM"}

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled inner-txn fee itxn {f.field} "
                f"<- {src} ({location}, {f.sub_id}); the attacker sets the fee the "
                f"app pays and can drain its balance via inflated fees — no "
                f"dominating check of the value (IR interprocedural)")
