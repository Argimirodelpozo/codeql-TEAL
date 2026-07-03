"""sec-guide/unsafe-division-order: precision loss from divide-before-multiply.

AVM integer division truncates toward zero, so ``(a / b) * c`` discards the
remainder of ``a / b`` *before* scaling by ``c`` — losing up to ``c - 1`` units
versus the mathematically-equal ``(a * c) / b``, which truncates only once, at the
end. In share-price / exchange-rate / reward math this is a systematic value leak
(rounding always favours one side), and it is the single most common arithmetic
bug auditors find in DeFi contracts.

The detector is a def-use shape match on the SSA: a multiply (``*`` / ``b*``)
whose operand is produced *directly* by a divide (``/`` / ``b/`` / ``divw``). That
is the divide-before-multiply order; reordering to multiply-first is the standard
fix. A divide by the literal ``1`` (a no-op that never truncates) is excluded.

This is a correctness/precision smell, not an exploit primitive, so it is reported
at MEDIUM and is intentionally a "review this expression" signal: a contract that
*intends* floor-then-scale semantics is rare but legitimate, and the finding points
the auditor straight at the expression to confirm.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.tealtools.ssa import Assignment, Phi, SSAProgram, SSAVar, const_int

_DIV_OPS = frozenset({"/", "b/", "divw"})
_MUL_OPS = frozenset({"*", "b*"})


@dataclass
class UnsafeDivisionOrderViolation:
    mul: Assignment
    div: Assignment

    @property
    def location(self) -> str:
        return common.loc(self.mul)

    @property
    def file(self) -> str:
        return self.mul.location.file

    @property
    def line(self) -> int:
        # Structured anchor for machine output; mirrors the mul anchor in pretty()/location.
        return self.mul.location.line

    def pretty(self) -> str:
        return (
            f"divide-before-multiply at {self.location}: a `{self.div.op}` result "
            f"is multiplied by `{self.mul.op}` (div at {common.loc(self.div)}). "
            f"Integer division truncates first, so precision is lost — reorder to "
            f"multiply before dividing (`(a * c) / b`)."
        )

    def to_dict(self) -> dict:
        return {
            "location": self.location,
            "div_location": common.loc(self.div),
            "div_op": self.div.op,
            "mul_op": self.mul.op,
            "message": self.pretty(),
        }

    def __repr__(self) -> str:
        return f"UnsafeDivisionOrderViolation({self.pretty()})"


class UnsafeDivisionOrderDetector:
    name: ClassVar[str] = "sec-guide/unsafe-division-order"
    # Arithmetic precision is contract-kind-agnostic (apps and lsigs both do math).
    applies_to: ClassVar[frozenset] = frozenset({"app", "logicsig"})
    violation_cls: ClassVar[type] = UnsafeDivisionOrderViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list:
        out: list = []
        for a in self.prog.assignments:
            if a.op not in _MUL_OPS:
                continue
            if not common.file_match(a.location.file, self.file):
                continue
            for inp in a.inputs:
                div = self._div_def(inp)
                if div is not None and not _divides_by_one(div):
                    out.append(UnsafeDivisionOrderViolation(mul=a, div=div))
                    break          # one finding per multiply
        return out

    def _div_def(self, operand, seen=None) -> Optional[Assignment]:
        """The divide ``Assignment`` whose result reaches ``operand`` through
        value-preserving copies, or None. Follows the direct def, the scratch
        store→load bridge (``store N`` / ``load N`` — how Puya/PyTeal hold an
        intermediate), and phi joins — but NOT through other arithmetic, since a
        value that has been combined further is no longer "the divided value
        being scaled". MAY semantics (any reaching div counts): this is a
        precision smell and recall matters."""
        if seen is None:
            seen = set()
        if operand in seen:
            return None
        if isinstance(operand, Phi):                  # phi join (any arg counts)
            seen.add(operand)
            for arg in operand.args:
                found = self._div_def(arg, seen)
                if found is not None:
                    return found
            return None
        if not isinstance(operand, SSAVar):
            return None
        seen.add(operand)
        d = operand.defined_by
        if d is None:
            return None
        if d.op in _DIV_OPS:
            return d
        if d.op == "load":                            # scratch reaching-def
            for s in (common._scratch_stores_for(self.prog, operand) or ()):
                found = self._div_def(self.prog.var(*s), seen)
                if found is not None:
                    return found
        return None


def _divides_by_one(div: Assignment) -> bool:
    """A divide whose divisor is the literal 1 — a no-op that never truncates, so
    the multiply order is irrelevant. inputs are top-of-stack first, so the
    divisor (the second `/` operand) is inputs[0]."""
    return bool(div.inputs) and const_int(div.inputs[0]) == 1
