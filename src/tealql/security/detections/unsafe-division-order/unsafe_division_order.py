"""sec-guide/unsafe-division-order: a multiply whose operand comes directly from a
divide. AVM integer division truncates toward zero, so ``(a / b) * c`` discards
the remainder before scaling and loses up to ``c - 1`` units versus the equal
``(a * c) / b``, which truncates once. A divide by literal ``1`` is excluded.

A precision SMELL, not an exploit primitive — floor-then-scale is rare but
legitimate, so this is a "review this expression" signal at MEDIUM.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security._program_shape import file_match, loc
from tealql.security._value_flow import _scratch_stores_for
from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import Assignment, Phi, SSAProgram, SSAVar, const_int

_DIV_OPS = frozenset({"/", "b/", "divw"})
_MUL_OPS = frozenset({"*", "b*"})


@dataclass
class UnsafeDivisionOrderViolation:
    mul: Assignment
    div: Assignment

    @property
    def location(self) -> str:
        return loc(self.mul)

    @property
    def file(self) -> str:
        return self.mul.location.file

    @property
    def line(self) -> int:
        # Must mirror the mul anchor in pretty()/location.
        return self.mul.location.line

    def pretty(self) -> str:
        return (
            f"divide-before-multiply at {self.location}: a `{self.div.op}` result "
            f"is multiplied by `{self.mul.op}` (div at {loc(self.div)}). "
            f"Integer division truncates first, so precision is lost — reorder to "
            f"multiply before dividing (`(a * c) / b`)."
        )

    def to_dict(self) -> dict:
        return {
            "location": self.location,
            "div_location": loc(self.div),
            "div_op": self.div.op,
            "mul_op": self.mul.op,
            "message": self.pretty(),
        }

    def __repr__(self) -> str:
        return f"UnsafeDivisionOrderViolation({self.pretty()})"


class UnsafeDivisionOrderDetector:
    name: ClassVar[str] = "sec-guide/unsafe-division-order"
    # Arithmetic precision is contract-kind-agnostic.
    applies_to: ClassVar[frozenset] = frozenset({"app", "logicsig"})
    violation_cls: ClassVar[type] = UnsafeDivisionOrderViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file
        self._facts = prog.facts(FactDomain.CONSTANTS)

    def detect(self) -> list:
        out: list = []
        for a in self.prog.assignments:
            if a.op not in _MUL_OPS:
                continue
            if not file_match(a.location.file, self.file):
                continue
            for inp in a.inputs:
                div = self._div_def(inp)
                if div is not None and not _divides_by_one(div):
                    out.append(UnsafeDivisionOrderViolation(mul=a, div=div))
                    break          # one finding per multiply
        return out

    def _div_def(self, operand, seen=None) -> Optional[Assignment]:
        """The divide whose result reaches ``operand`` through value-preserving
        copies (direct def, scratch store→load, phi), else ``None``. NOT through
        other arithmetic — a further-combined value is no longer "the divided value
        being scaled". MAY semantics: recall matters for a precision smell."""
        if seen is None:
            seen = set()
        operand = self._facts.resolve(operand)
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
            for s in (_scratch_stores_for(self.prog, operand) or ()):
                found = self._div_def(self.prog.var(*s), seen)
                if found is not None:
                    return found
        return None


def _divides_by_one(div: Assignment) -> bool:
    """A divide by literal 1 — a no-op that never truncates.

    HAZARD: inputs are TOP-FIRST, so the divisor (the second ``/`` operand) is
    ``inputs[0]``, not ``inputs[1]``."""
    return bool(div.inputs) and const_int(div.inputs[0]) == 1
