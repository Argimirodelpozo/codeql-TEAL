"""sec-guide/partial-tainted-fund-flow: byte-precise fund-flow (validation bypass).

The boolean tainted-fund-flow detector reasons at *input-slot* granularity: a
guard is "a check derived from the same ApplicationArgs slot". That is too coarse
when a contract packs several logical fields into ONE argument and validates only
some of them — validating ``arg[0..2]`` (a length / selector / discriminator)
suppresses a finding on ``arg[2..34]`` (an embedded address that flows to
``Receiver``), even though the bytes that actually steer the funds were never
checked. A real **partial-validation bypass**, and a false negative for the
slot-granular detector.

This detector closes that gap with the **byte-interval taint** engine
(:func:`tealql.tealtools.dataflow.byte_taint.byte_taint`, ``validate=True``): taint is
tracked per byte-offset, and an ``assert(slice == const)`` clears only the exact
bytes it pins. A payment sink whose value still carries tainted (un-validated)
bytes after narrowing is attacker-controlled at the byte level.

To stay precise and non-overlapping, it reports only the **net-new** findings the
boolean detector misses: it runs tainted-fund-flow first and subtracts whatever it
already flags (the plain whole-value cases). What remains is exactly the
partial-validation class — the contract DID validate the argument, just not the
bytes on the funds path. Sender/creator-gated sinks are suppressed (shared
machinery), and a sink whose flowing bytes ARE validated is cleared by the
narrowing, so it never reaches here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.security.detections.tainted_fund_flow import TaintedFundFlowDetector
from tealql.tealtools.dataflow.byte_taint import Intervals, byte_taint
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.avm import PAYMENT_FUND_FIELDS

_FUND_FIELDS = PAYMENT_FUND_FIELDS


def _byte_sources(a):
    """Seed every user-input read (ApplicationArgs / LogicSig args) as fully
    tainted at byte granularity — the same source universe as the boolean
    tainted-fund-flow detector, so the subtraction below lines up."""
    lbl = common.source_label(a.op, a.immediates.strip())
    if lbl and a.outputs:
        return Intervals.whole()
    return None


def _cached_byte_taint(prog: SSAProgram):
    """The byte-interval taint fixpoint, memoised on ``prog``. ``byte_taint`` is
    program-wide (no file scope) and this detector always runs it with the same
    ``_byte_sources`` / ``validate=True`` config, so one result serves every file
    in a multi-file program — without the cache the scanner re-ran the whole
    fixpoint over the entire directory once per file."""
    bt = getattr(prog, "_sec_partial_byte_taint", None)
    if bt is None:
        bt = byte_taint(prog, sources=_byte_sources, validate=True)
        try:
            prog._sec_partial_byte_taint = bt
        except Exception:
            pass
    return bt


@dataclass
class PartialTaintedFundFlowViolation:
    prog: SSAProgram
    field: str = ""
    severity: str = ""
    byte_range: str = ""
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "byte_range": self.byte_range,
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"PartialTaintedFundFlowViolation({self.message})"


class PartialTaintedFundFlowDetector:
    name: ClassVar[str] = "sec-guide/partial-tainted-fund-flow"
    applies_to: ClassVar[frozenset] = frozenset({"app"})
    violation_cls: ClassVar[type] = PartialTaintedFundFlowViolation
    # The IR sibling computes byte-taint on the same substrate but adds
    # across-callsub guard dominance + interprocedural frame-resolved taint; it
    # falls back to THIS detector when the contract doesn't lift.
    superseded_by: ClassVar[str] = "ir-partial-tainted-fund-flow"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        # Net-new only: subtract what the boolean detector already flags so we
        # surface exactly the byte-precision (partial-validation) class.
        already = {
            (v.field, v.location)
            for v in TaintedFundFlowDetector(
                self.prog, file=self.file, path_predicates=self.pp).detect()
        }
        bt = _cached_byte_taint(self.prog)
        sender_vars = common.sender_creator_vars(self.prog, file=self.file)
        violations: list = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field not in _FUND_FIELDS:
                continue
            iv = bt.tainted_bytes(fs.value)
            scalar = bt.is_scalar_tainted(fs.value)
            if not iv and not scalar:
                continue                              # no un-validated bytes flow
            loc = common.loc(fs.assignment)
            if (fs.field, loc) in already:
                continue                              # boolean detector owns it
            if common.itxn_value_guarded(
                self.prog, self.pp, fs.assignment, frozenset(), {}, sender_vars):
                continue                              # sender/creator-gated
            sev = _FUND_FIELDS[fs.field]
            rng = str(iv) if iv else "scalar"
            hint = " (32 bytes — address-sized)" if iv and _is_addr_sized(iv) else ""
            msg = (f"[{sev}] partially-validated attacker bytes reach itxn "
                   f"{fs.field} ({loc}); tainted byte range {rng}{hint} on the "
                   f"funds path is unchecked — the argument is validated elsewhere "
                   f"but not on these bytes")
            violations.append(PartialTaintedFundFlowViolation(
                self.prog, fs.field, sev, rng, loc, msg))
        return violations


def _is_addr_sized(iv: Intervals) -> bool:
    """A single contiguous 32-byte tainted window — i.e. an embedded address."""
    parts = list(getattr(iv, "parts", ()) or ())
    return len(parts) == 1 and (parts[0][1] - parts[0][0]) == 32
