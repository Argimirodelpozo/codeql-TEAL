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
caller predicates across ``callsub`` edges). The TAINT precondition, however, is
INTRA-PROCEDURAL: the SSA def-use relation does not carry the ``proto``-frame
param-passing connection (a ``frame_dig`` has no def-use input; the caller->param
flow is reconstructed only by the lift), so a tainted value passed INTO a
subroutine as a parameter is not seen as tainted at a sink inside that callee. The
common inline pattern (the itxn is built in the same routine that reads the user
input) is fully covered; the param-fed minority is a known false-negative -- the
IR-layer ``WIP_lift2puyaIR.fund_flow`` keeps interprocedural taint (the lift
resolves frames into explicit params).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealtools.detections import common
from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import SSAProgram, SSAVar
from tealtools.opsets import (
    PAYMENT_FUND_FIELDS, TXN_SOURCE_OPS, ITXN_SOURCE_OPS, LSIG_ARG_OPS,
)

# Payment fields where attacker control = redirected / oversized fund movement.
_FUND_FIELDS = PAYMENT_FUND_FIELDS
_APPARGS_OPS = TXN_SOURCE_OPS
_LSIG_ARG_OPS = LSIG_ARG_OPS
_ITXN_LOG_OPS = ITXN_SOURCE_OPS
_CMP_OPS = frozenset({"==", "!="})


def _source_label(op: str, imm: str) -> Optional[str]:
    """The user-input source family an op reads, or None."""
    if op in _APPARGS_OPS and "ApplicationArgs" in imm:
        return "ApplicationArgs"
    if op in _LSIG_ARG_OPS:
        return "LogicSigArgs"
    if op in _ITXN_LOG_OPS and "LastLog" in imm:
        return "ItxnLastLog"
    return None


def _user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    """``{SSAVar|Phi: frozenset[(label, slot)]}`` -- forward taint from the
    user-input sources over the SSA def-use / phi / scratch relation, where ``slot``
    = ``(op, immediates)`` so two reads of the SAME input slot match (and
    ``ApplicationArgs[0]`` vs ``[1]`` don't)."""
    taint: dict = {}

    def t(o):
        return taint.get(o, frozenset())

    for a in prog.assignments:                       # seed
        if not common.file_match(a.location.file, file):
            continue
        lbl = _source_label(a.op, a.immediates.strip())
        if lbl:
            key = (lbl, (a.op, a.immediates.strip()))
            for o in a.outputs:
                if isinstance(o, SSAVar):
                    taint[o] = t(o) | {key}

    changed = True
    while changed:
        changed = False
        for ph in prog.phis.values():                # phi: union of args
            new = set()
            for arg in ph.args:
                new |= t(arg)
            if new - t(ph):
                taint[ph] = t(ph) | new
                changed = True
        for a in prog.assignments:
            if not common.file_match(a.location.file, file):
                continue
            ins = set()
            for inp in a.inputs:
                ins |= t(inp)
            if a.op == "load":                       # scratch reaching-def
                for o in a.outputs:
                    for s in (common._scratch_stores_for(prog, o) or ()):
                        ins |= t(prog.var(*s))
            if not ins:
                continue
            for o in a.outputs:
                if isinstance(o, SSAVar) and (ins - t(o)):
                    taint[o] = t(o) | ins
                    changed = True
    return {k: frozenset(v) for k, v in taint.items() if v}


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
        taint = _user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = self._sender_vars()
        violations = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field not in _FUND_FIELDS:
                continue
            sink_slots = taint.get(fs.value, frozenset())
            if not sink_slots:
                continue                              # not attacker-controlled
            a = fs.assignment
            preds = self.pp.predicates_at(file=a.location.file, line=a.location.line)
            if any(self._is_guarded(p, sink_slots, taint, sender_vars) for p in preds):
                continue
            sources = tuple(sorted({lbl for lbl, _ in sink_slots}))
            sev = _FUND_FIELDS[fs.field]
            loc = common.loc(a)
            msg = (f"[{sev}] attacker-controlled itxn {fs.field} <- "
                   f"{'+'.join(sources)} ({loc}); no dominating check of the "
                   f"value or txn Sender")
            violations.append(TaintedFundFlowViolation(
                self.prog, fs.field, sev, sources, loc, msg))
        return violations

    # -- internals ------------------------------------------------------

    def _sender_vars(self) -> set:
        sv: set = set()
        for a in common.txn_field_reads(self.prog, "Sender", file=self.file):
            sv |= {o for o in a.outputs if isinstance(o, SSAVar)}
        for a in common.global_field_reads(self.prog, "CreatorAddress", file=self.file):
            sv |= {o for o in a.outputs if isinstance(o, SSAVar)}
        return sv

    def _is_guarded(self, cond, sink_slots, taint, sender_vars) -> bool:
        v = cond.value
        # value-check: the predicate derives from the SAME input slot (taint
        # propagates through the comparison, so `arg < N` carries arg's slot).
        if taint.get(v, frozenset()) & sink_slots:
            return True
        # sender-check: a comparison consuming txn Sender / Global.CreatorAddress.
        d = getattr(v, "defined_by", None)
        if d is not None and d.op in _CMP_OPS and any(
                common._operand_flows_from_field_var(self.prog, op, sender_vars)
                for op in d.inputs):
            return True
        return False
