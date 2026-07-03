"""sec-guide/ir-tainted-fund-flow: attacker-controlled inner-txn fund flow (IR).

The interprocedural-IR PRIMARY fund-flow detector (run on the lifted Puya IR via
:func:`common.ir_lifter`). An attacker-controlled value reaching a fund-flow
inner-transaction field (``Receiver`` / ``Amount`` / ``CloseRemainderTo`` /
``RekeyTo`` / asset variants) without a dominating guard lets the attacker
redirect, size, or sweep a payment.

It matches or beats the SSA ``tainted-fund-flow`` on every analysis axis -- the
key edge being **guard dominance across a ``callsub``**: ``PathPredicateAnalysis``
is context-INSENSITIVE there, so an owner/sender check before a callsub on the
path to the sink is lost at the multi-caller return merge (a false positive the IR
clears by computing dominance within the lifted subroutine). The SSA detector is
marked ``superseded_by`` this one and skipped in default scans; this detector
falls back to it when the lift fails, so it is the single complete entry point.
Emits only the UNGUARDED, call-resolved flows.
"""
from __future__ import annotations

from tealql.tealtools.opsets import FUND_FIELDS

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
