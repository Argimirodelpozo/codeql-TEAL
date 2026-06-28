"""sec-guide/ir-tainted-fund-flow: attacker-controlled inner-txn fund flow (IR layer).

The interprocedural-IR sibling of :mod:`tainted_fund_flow` (the SSA-layer
detector), run on the lifted Puya-shaped IR via :func:`common.ir_lifter`. An
attacker-controlled value reaching a fund-flow inner-transaction field
(``Receiver`` / ``Amount`` / ``CloseRemainderTo`` / ``RekeyTo`` / asset variants)
without a dominating guard lets the attacker redirect, size, or sweep a payment.

Why an IR sibling rather than only the SSA detector -- a precision axis the SSA
layer can't reach, confirmed against real mainnet (app_1300008693): **guard
dominance across a ``callsub``**. The IR computes dominance *within* the lifted
subroutine, where an ``InvokeSubroutine`` between a check and the sink does not
break the assert->sink dominance. The SSA ``PathPredicateAnalysis`` is context-
INSENSITIVE across ``callsub`` -- so an owner/sender check (e.g.
``txn Sender == app_global_get("owner")``) sitting before a ``callsub`` on the
path to the sink is lost at the multi-caller return merge, and the flow is
reported UNGUARDED: a false positive the IR layer avoids (the SSA over-reported a
whole owner-gated handler template ~29x on one corpus sample; the IR cleared it).

This is a COMPLEMENTARY sibling, not a strict replacement: the SSA detector keeps
its own strengths (cross-contract guard reasoning via ``path_predicates``; the
``guard = same-taint-slot overlap`` value check), and the two layers can disagree
the other way on intricate intra-procedural guards (a bypassable validation
helper). Run both; treat the IR layer as the across-``callsub`` guard authority.

Emits only the UNGUARDED, call-resolved flows as violations; the underlying
analysis also lists guarded flows, but those are for human triage, not findings.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common


@dataclass
class IrTaintedFundFlowViolation:
    fundfield: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "field": self.fundfield,
            "severity": self.severity,
            "sources": list(self.sources),
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"IrTaintedFundFlowViolation({self.message})"


class IrTaintedFundFlowDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-fund-flow"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # inner txns are app-only
    violation_cls: ClassVar[type] = IrTaintedFundFlowViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset()):
        self.prog = prog
        self.file = file
        # ApplicationArgs indices a CALLER pinned to constants (cross-contract):
        # the cross-contract runner passes the call site's const_args, so a callee
        # payment fixed by its caller isn't reported attacker-controlled here.
        self.trusted_args = frozenset(trusted_args)

    def detect(self) -> list:
        lifter = common.ir_lifter(self.prog, self.file)
        if lifter is None:                       # contract didn't lift (rare)
            return []
        from tealtools.WIP_lift2puyaIR import fund_flow as FF

        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in FF.tainted_fund_flows(lifter, trusted_args=self.trusted_args):
            # Guarded flows are reported by the analysis for triage; only an
            # UNGUARDED, call-RESOLVED flow is a violation. ``param_derived`` means
            # a param feeds it but the sub has no call site to resolve the guard
            # (dead / externally-entered) -- excluded to stay precise.
            if f.guarded or f.param_derived:
                continue
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            message = (
                f"[{f.severity}] attacker-controlled itxn {f.field} <- "
                f"{'+'.join(sources)} ({location}, {f.sub_id}); no dominating "
                f"check of the value or txn Sender (IR interprocedural)")
            out.append(IrTaintedFundFlowViolation(
                f.field, f.severity, sources, location, message))
        return out
