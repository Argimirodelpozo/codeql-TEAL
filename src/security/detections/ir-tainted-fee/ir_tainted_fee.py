"""sec-guide/ir-tainted-fee: attacker-controlled inner-transaction fee (IR).

A user-input-tainted ``itxn_field Fee`` lets the attacker choose the fee the app
pays on an inner transaction -- set it large and drain the app's algo balance one
inflated inner txn at a time. Distinct from the ``inner-txn-fee`` detector, which
flags a CONSTANT non-zero fee and explicitly skips dynamic ones; this covers
exactly that skipped attacker-controlled case. A new capability (no SSA sibling);
lift-only.
"""
from __future__ import annotations

from security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


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
