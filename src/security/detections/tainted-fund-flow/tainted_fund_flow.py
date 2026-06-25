"""sec-guide/tainted-fund-flow: attacker-controlled inner-transaction payment.

A user-input-tainted value reaching an inner-transaction ``Receiver`` /
``AssetReceiver`` / ``Amount`` / ``AssetAmount`` that is NOT dominated by a check
of that value or the transaction ``Sender`` -- the attacker can redirect a payment
or control how much moves. (``RekeyTo`` / ``CloseRemainderTo`` / ``AssetCloseTo``
have their own dedicated validators; this detector covers the payment fields they
don't, and adds the user-input precondition those taint-free validators lack.)

Lives at the SSA layer so it reuses the existing machinery rather than a parallel
engine: :func:`common.inner_txn_field_assigns` (sinks), a forward user-input taint
over the PySSA def-use/phi/scratch relation (precondition + value-check), and
:class:`PathPredicateAnalysis` (guard dominance). Because taint propagates through
all ops, a guard like ``arg < 100`` is automatically tainted by the same input
slot, so the value-check is just a taint-slot overlap; the sender-check reuses
:func:`common._operand_flows_from_field_var` (Sender is a direct read).

GUARD dominance is interprocedural for free (``PathPredicateAnalysis`` propagates
caller predicates across ``callsub`` edges), and so is the TAINT now: the base
SSA def-use relation leaves ``frame_dig`` disconnected, but ``_user_input_taint``
unions each ``frame_dig`` param read's taint from the caller args bound to it
(:func:`tealtools.passes.frame_flow.frame_param_sources`), so a value fed INTO a
subroutine parameter and paid out inside the callee is caught natively — no IR
lift, no per-detector supplement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common
from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import SSAProgram
from tealtools.opsets import PAYMENT_FUND_FIELDS

# Payment fields where attacker control = redirected / oversized fund movement.
_FUND_FIELDS = PAYMENT_FUND_FIELDS


@dataclass
class TaintedFundFlowViolation:
    prog: SSAProgram
    field: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "sources": list(self.sources),
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"TaintedFundFlowViolation({self.message})"


class TaintedFundFlowDetector:
    name: ClassVar[str] = "sec-guide/tainted-fund-flow"
    applies_to: ClassVar[frozenset] = frozenset({"app"})
    violation_cls: ClassVar[type] = TaintedFundFlowViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        if getattr(prog, "_materialized", False):
            raise ValueError(
                "TaintedFundFlowDetector requires the pre-materialized SSA "
                "representation (path predicates + def-use traversal)."
            )
        if getattr(prog, "_dead_eliminated", False):
            raise ValueError(
                "TaintedFundFlowDetector requires the pre-dead-elimination SSA."
            )
        self.prog = prog
        self.file = file
        # Accept a pre-built (e.g. caller-SEEDED) PathPredicateAnalysis so the
        # cross-contract runner (detections.xcontract._construct_detector) can feed
        # the callee's seeded predicates -- a caller that pins an ApplicationArgs
        # slot to a constant then guards the fund field fed by that slot.
        self.pp = path_predicates or PathPredicateAnalysis(prog)

    def detect(self) -> list:
        taint = common.user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = common.sender_creator_vars(self.prog, file=self.file)
        violations: list = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field not in _FUND_FIELDS:
                continue
            sink_slots = taint.get(fs.value, frozenset())
            if not sink_slots:
                continue                              # not attacker-controlled
            if common.itxn_value_guarded(
                self.prog, self.pp, fs.assignment, sink_slots, taint, sender_vars):
                continue
            sources = tuple(sorted({lbl for lbl, _ in sink_slots}))
            sev = _FUND_FIELDS[fs.field]
            loc = common.loc(fs.assignment)
            msg = (f"[{sev}] attacker-controlled itxn {fs.field} <- "
                   f"{'+'.join(sources)} ({loc}); no dominating check of the "
                   f"value or txn Sender")
            violations.append(TaintedFundFlowViolation(
                self.prog, fs.field, sev, sources, loc, msg))
        return violations
