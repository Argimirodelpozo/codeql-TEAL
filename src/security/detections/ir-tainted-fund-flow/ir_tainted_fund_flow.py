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

This is now the PRIMARY fund-flow detector: it matches or beats the SSA
``tainted-fund-flow`` on every analysis axis (across-``callsub`` dominance,
validation-subroutine guards, typed reasoning, AND cross-contract caller-pinned
suppression), so that detector is marked ``superseded_by`` this one and skipped in
default scans. When the lift fails (~0.1% of real mainnet) this detector falls
back to the SSA one, so it gives complete coverage from a single entry point. The
one corpus case where the two ever diverged (app_1050027991) is not an IR false
positive: its close/asset-close findings are corroborated by the SSA's dedicated
``close-remainder-to`` / ``asset-close-to`` detectors, and its amount finding is a
defensible higher-recall flag on a user-influenced payout.

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

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        # ApplicationArgs indices a CALLER pinned to constants (cross-contract):
        # the cross-contract runner passes the call site's const_args, so a callee
        # payment fixed by its caller isn't reported attacker-controlled here.
        self.trusted_args = frozenset(trusted_args)
        # Forwarded to the SSA fallback (below) so it keeps cross-contract guard
        # seeding when the lift fails.
        self.path_predicates = path_predicates

    def detect(self) -> list:
        lifter = common.ir_lifter(self.prog, self.file)
        if lifter is None:
            # The contract didn't lift (~0.1% of real mainnet). Fall back to the
            # SSA tainted-fund-flow detector (which needs no lift) so this detector
            # gives COMPLETE coverage and can be the single fund-flow entry point.
            from security import DETECTORS
            return DETECTORS["tainted-fund-flow"](
                self.prog, file=self.file, path_predicates=self.path_predicates,
            ).detect()
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
