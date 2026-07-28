"""sec-guide/ir-tainted-fund-flow: the PRIMARY fund-flow detector, on the lifted
Puya IR. An attacker-controlled value reaching a ``FUND_FIELDS`` inner-txn field
without a dominating guard lets the attacker redirect, size, or sweep a payment.

``FUND_FIELDS`` excludes ``RekeyTo`` — an app/itxn rekey is self-inflicted and
belongs to ``inner-txn-close-rekey``.

The IR's edge over the SSA sibling is guard dominance across a ``callsub``:
``PathPredicateAnalysis`` is context-INSENSITIVE there, so an owner check before a
callsub is lost at the multi-caller return merge. This detector falls back to the
SSA one when the lift fails, making it the single complete entry point.
"""
from __future__ import annotations

from tealql.tealtools.avm import FUND_FIELDS

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrTaintedFundFlowViolation(_IrTaintSinkViolation):
    pass


class IrTaintedFundFlowDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-fund-flow"
    violation_cls = IrTaintedFundFlowViolation
    fields = FUND_FIELDS
    fallback = "tainted-fund-flow"

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled itxn {f.field} <- {src} "
                f"({location}, {f.sub_id}); no dominating check of the value or txn "
                f"Sender (IR interprocedural)")
