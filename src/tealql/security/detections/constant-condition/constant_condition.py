"""sec-guide/constant-condition: a guard the static range layer proves is fixed at
compile time — a vacuous ``assert`` (always true, enforces nothing), an
unsatisfiable one (always false, everything past it dead), or a ``bnz``/``bz``
with one dead arm.

Ranges come from immutable value facts, never assertion-conditioned facts, so
the detector's answer is independent of which other analysis ran first.

Sound by construction: reported only when the operand ranges PROVE the outcome
(disjoint or fully-ordered intervals). Compound ``&&``/``||`` conditions are not
decomposed, and pure-constant conditions (``assert(1)``, ``0 < 1``) are skipped as
compiler-emitted folding — so a finding always involves a non-constant value.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import Const, IntRange, Location, SSAProgram, binary_operands

# uint64 comparison ops, in the top-first ``inputs[1] OP inputs[0]`` form.
_CMP = frozenset({"<", "<=", ">", ">=", "==", "!="})


def _eval_cmp(op: str, lr: IntRange, rr: IntRange) -> Optional[int]:
    """The constant truth value of ``lr OP rr`` when the ranges PROVE it (disjoint
    or fully-ordered intervals), else ``None``."""
    if op == "<":
        if lr.hi < rr.lo:
            return 1
        if lr.lo >= rr.hi:
            return 0
    elif op == "<=":
        if lr.hi <= rr.lo:
            return 1
        if lr.lo > rr.hi:
            return 0
    elif op == ">":
        if lr.lo > rr.hi:
            return 1
        if lr.hi <= rr.lo:
            return 0
    elif op == ">=":
        if lr.lo >= rr.hi:
            return 1
        if lr.hi < rr.lo:
            return 0
    elif op == "==":
        if lr.hi < rr.lo or rr.hi < lr.lo:
            return 0
        if lr.lo == lr.hi == rr.lo == rr.hi:
            return 1
    elif op == "!=":
        if lr.hi < rr.lo or rr.hi < lr.lo:
            return 1
        if lr.lo == lr.hi == rr.lo == rr.hi:
            return 0
    return None


@dataclass
class ConstantConditionViolation:
    kind: str            # "vacuous-assert" | "unsatisfiable-assert" | "constant-branch"
    location: Location
    op: str              # the op whose condition is constant ("assert"/"bnz"/"bz")
    value: int           # the proven condition value (1 = always true / non-zero)
    detail: str          # the proven sub-expression, e.g. "OnCompletion <= 6"

    @property
    def file(self) -> str:
        return self.location.file

    @property
    def line(self) -> int:
        return self.location.line

    def pretty(self) -> str:
        where = str(self.location)
        if self.kind == "vacuous-assert":
            return (
                f"Vacuous assert at {where}: `{self.detail}` is always true "
                "given the values that can reach it, so the guard enforces "
                "nothing (false sense of protection)."
            )
        if self.kind == "unsatisfiable-assert":
            return (
                f"Unsatisfiable assert at {where}: `{self.detail}` is always "
                "false, so execution always rejects here — code beyond it is "
                "dead (likely a logic bug)."
            )
        arm = "always taken" if self.value else "never taken"
        return (
            f"Constant branch at {where}: `{self.op}` condition `{self.detail}` "
            f"is a compile-time constant ({arm}) — one arm is unreachable."
        )

    def __repr__(self) -> str:
        return f"ConstantConditionViolation({self.pretty()})"


class ConstantConditionDetector:
    name = "sec-guide/constant-condition"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file
        self.facts = prog.facts(FactDomain.CONSTANTS, FactDomain.RANGES)

    def _describe(self, cond) -> str:
        """A short label: ``lhs OP rhs`` for a comparison, else the var's own."""
        d = getattr(cond, "defined_by", None)
        if d is not None and d.op in _CMP and len(d.inputs) == 2:
            lhs, rhs = binary_operands(d)
            return f"{_label(lhs, self.facts)} {d.op} {_label(rhs, self.facts)}"
        return _label(cond, self.facts)

    def _cond_const(self, cond) -> Optional[int]:
        """1 if ``cond`` is provably non-zero, 0 if provably zero, else ``None`` —
        a comparison from its operand ranges, anything else from its own.
        Pure-constant conditions return ``None`` (compiler folding, not a guard)."""
        d = getattr(cond, "defined_by", None)
        if d is not None and d.op in _CMP and len(d.inputs) == 2:
            lhs, rhs = binary_operands(d)
            if self.facts.constant(lhs) is not None and self.facts.constant(rhs) is not None:
                return None
            lr = self.facts.int_range(lhs)
            rr = self.facts.int_range(rhs)
            if lr is not None and rr is not None:
                return _eval_cmp(d.op, lr, rr)
            return None
        if isinstance(cond, Const) or self.facts.constant(cond) is not None:
            return None
        r = self.facts.int_range(cond)
        if r is not None:
            if r.lo >= 1:
                return 1
            if r.lo == 0 and r.hi == 0:
                return 0
        return None

    def detect(self) -> list[ConstantConditionViolation]:
        out: list[ConstantConditionViolation] = []
        for a in self.prog.assignments:
            if self.file is not None and a.location.file != self.file:
                continue
            if not a.inputs:
                continue
            if a.op == "assert":
                c = self._cond_const(a.inputs[0])
                if c == 1:
                    out.append(ConstantConditionViolation(
                        "vacuous-assert", a.location, "assert", 1,
                        self._describe(a.inputs[0])))
                elif c == 0:
                    out.append(ConstantConditionViolation(
                        "unsatisfiable-assert", a.location, "assert", 0,
                        self._describe(a.inputs[0])))
            elif a.op in ("bnz", "bz"):
                c = self._cond_const(a.inputs[0])
                if c is not None:
                    out.append(ConstantConditionViolation(
                        "constant-branch", a.location, a.op, c,
                        self._describe(a.inputs[0])))
        return out


def _label(operand, facts) -> str:
    """Best-effort short label for an operand in a finding message."""
    d = getattr(operand, "defined_by", None)
    if d is not None and d.op in ("txn", "gtxn", "gtxns", "itxn", "global"):
        return d.immediates or d.op
    cv = facts.constant(operand)
    if cv is not None:
        return getattr(cv, "value", str(cv))
    if isinstance(operand, Const):
        return getattr(operand, "value", str(operand))
    return str(operand)
