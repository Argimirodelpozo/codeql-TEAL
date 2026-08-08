"""sec-guide/tainted-fund-flow: a user-input-tainted value reaching an inner-txn
``Receiver``/``AssetReceiver``/``Amount``/``AssetAmount`` with no dominating check
of that value or of ``txn Sender`` — the attacker redirects a payment or controls
how much moves. ``RekeyTo``/``CloseRemainderTo``/``AssetCloseTo`` have their own
validators; this owns the payment fields and adds the user-input precondition
those taint-free validators lack.

Taint propagates through every op, so a guard like ``arg < 100`` carries the same
input slot and the value-check is just a taint-slot overlap. Both taint and guard
dominance are interprocedural: predicates cross ``callsub`` edges and each
``frame_dig`` param read inherits the caller args' taint.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.avm import PAYMENT_FUND_FIELDS

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
    # The IR sibling matches or beats this on every axis and falls back to THIS
    # detector when the lift fails, so it stays registered but is skipped in
    # default scans. ``only: [tainted-fund-flow]`` overrides.
    superseded_by: ClassVar[str] = "ir-tainted-fund-flow"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        self.prog = prog
        self.file = file
        # A pre-built analysis lets the cross-contract runner feed the callee's
        # caller-SEEDED predicates (a caller pinning an ApplicationArgs slot).
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        taint = common.user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = common.sender_vars(self.prog, file=self.file)
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
