"""sec-guide/partial-tainted-fund-flow: the partial-validation bypass the
slot-granular tainted-fund-flow detector misses.

When a contract packs several logical fields into ONE argument, validating
``arg[0..2]`` suppresses a slot-granular finding on ``arg[2..34]`` — an embedded
address flowing to ``Receiver`` that was never checked. Byte-interval taint
(``byte_taint(..., validate=True)``) tracks per byte-offset instead, so an
``assert(slice == const)`` clears only the bytes it actually pins.

Reports only NET-NEW findings: tainted-fund-flow runs first and whatever it flags
is subtracted, leaving exactly the partial-validation class.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.security.detections.tainted_fund_flow import TaintedFundFlowDetector
from tealql.tealtools.dataflow.byte_taint import Intervals, byte_taint
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram, SSAVar, Phi


# Ops reading a specific BYTE POSITION of a buffer. A scalar produced through one
# has partial sub-field provenance, so byte_taint's narrowing governs it; a scalar
# with none is a WHOLE value that byte_taint cannot clear (bounds check, non-slice
# equality) and must fall back to full value-slot guard reasoning.
_BYTE_POSITION_OPS = frozenset({
    "getbyte", "extract_uint16", "extract_uint32", "extract_uint64",
    "extract", "extract3", "substring", "substring3",
})


def _byte_extracted(value, seen=None) -> bool:
    """``value``'s def-tree reads a specific byte position, i.e. it has partial
    sub-field provenance (see :data:`_BYTE_POSITION_OPS`)."""
    if seen is None:
        seen = set()
    if value in seen:
        return False
    seen.add(value)
    if isinstance(value, Phi):
        return any(_byte_extracted(a, seen) for a in value.args)
    if not isinstance(value, SSAVar):
        return False
    d = getattr(value, "defined_by", None)
    if d is None:
        return False
    if d.op in _BYTE_POSITION_OPS:
        return True
    return any(_byte_extracted(i, seen) for i in (getattr(d, "inputs", ()) or ()))
from tealql.tealtools.avm import PAYMENT_FUND_FIELDS

_FUND_FIELDS = PAYMENT_FUND_FIELDS


def _byte_sources(a):
    """Seed every user-input read as fully tainted at byte granularity — the SAME
    source universe as tainted-fund-flow, or the net-new subtraction misaligns."""
    lbl = common.source_label(a.op, a.immediates.strip())
    if lbl and a.outputs:
        return Intervals.whole()
    return None


def _cached_byte_taint(prog: SSAProgram):
    """The byte-interval taint fixpoint, memoised on ``prog``. ``byte_taint`` is
    program-wide and always run with the same config here, so one result serves
    every file — uncached, the scanner reran the whole fixpoint per file."""
    bt = getattr(prog, "_sec_partial_byte_taint", None)
    if bt is None:
        bt = byte_taint(prog, sources=_byte_sources, validate=True)
        try:
            prog._sec_partial_byte_taint = bt
        except AttributeError:      # only if SSAProgram ever gains __slots__
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
    # The IR sibling adds across-callsub guard dominance + frame-resolved taint,
    # and falls back to THIS detector when the contract doesn't lift.
    superseded_by: ClassVar[str] = "ir-partial-tainted-fund-flow"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        # Net-new only: subtract what the boolean detector already flags.
        already = {
            (v.field, v.location)
            for v in TaintedFundFlowDetector(
                self.prog, file=self.file, path_predicates=self.pp).detect()
        }
        bt = _cached_byte_taint(self.prog)
        sender_vars = common.sender_creator_vars(self.prog, file=self.file)
        taint = common.user_input_taint(self.prog, self.file)   # input-slot map
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
            # HAZARD: guard reasoning splits by provenance. A byte-INTERVAL flow or
            # a byte-extracted scalar gets NO slots — byte_taint already did the
            # byte-level clearing, and an input-slot guard would reproduce the
            # sub-field blind spot. A WHOLE-VALUE scalar has no sub-field to be
            # blind to and byte_taint cannot clear its validation, so it needs the
            # full value-slot reasoning or a validated amount becomes an FP.
            slots = (taint.get(fs.value, frozenset())
                     if (not iv and not _byte_extracted(fs.value)) else frozenset())
            if common.itxn_value_guarded(
                self.prog, self.pp, fs.assignment, slots, taint, sender_vars):
                continue                              # sender-gated, or value-checked
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
