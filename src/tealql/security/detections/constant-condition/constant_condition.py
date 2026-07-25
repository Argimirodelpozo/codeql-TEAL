"""sec-guide/constant-condition: a guard whose outcome the range layer
proves is fixed at compile time.

Consumes the static integer-range layer (txn-family enum / count field
bounds, ``*_get`` exists flags, ``*_params_get`` value bounds, op-output
seeds, const->range and arithmetic composition) to flag guards that look
protective but constrain nothing:

  - **vacuous assert**       — ``assert(cond)`` where ``cond`` is provably
                               always non-zero, so the assert never halts
                               and enforces nothing (a false sense of
                               protection, e.g. ``assert(OnCompletion <= 6)``
                               when OnCompletion is structurally in [0, 5]).
  - **unsatisfiable assert** — ``assert(cond)`` where ``cond`` is provably
                               always zero, so the program rejects on every
                               path reaching it (dead code beyond / a bug).
  - **constant branch**      — ``bnz`` / ``bz`` whose condition is a
                               compile-time constant, so one arm is dead.

This deliberately does NOT run assert-refinement
(:meth:`SSAProgram.propagate_assert_ranges`): that tightens operands
*using* the asserts, which would make every asserted comparison look
vacuous. The ranges consumed here come from value *facts* (field
semantics, constants, arithmetic) only, so a flagged guard is genuinely
redundant given what the program structurally knows -- independent of any
assertion.

That is a precondition on the SHARED program, not just on this detector:
if anything ran the standard pass pipeline
(:func:`tealql.tealtools.passes.run_all_passes`, which includes assert
refinement) on the same ``SSAProgram`` first, every asserted comparison
reads as vacuous -- measured at 0 findings before, 87 after, on a sample
of real contracts. The detector cannot un-refine an annotation, so it
checks ``prog._assert_ranges_applied`` and declines to report rather than
emit a swarm of confident nonsense.

Sound by construction: a condition is reported only when its operand
ranges *prove* the outcome (disjoint or fully-ordered intervals); any
overlap yields no finding. Compound ``&&`` / ``||`` conditions are not
decomposed (no finding rather than a guess).

Precision: pure-constant conditions (both comparison operands literal, or
a bare literal condition — ``assert(1)``, ``0 < 1``, ``int 0; bnz``) are
skipped. Those are compiler-emitted constant folding, not a guard that
*looks* like it constrains a runtime value, so a finding always involves
at least one non-constant value (a field read, input, or computed
result). On a 120-contract sample of compiled/real TEAL this drops the
finding count from 64 (all boilerplate) to 0.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import IntRange, Location, SSAProgram, binary_operands, is_const
from tealql.tealtools.passes.range_arith import _operand_range

logger = logging.getLogger("tealql.security.constant-condition")

# uint64 comparison ops, in the top-first ``inputs[1] OP inputs[0]`` form.
_CMP = frozenset({"<", "<=", ">", ">=", "==", "!="})


def _eval_cmp(op: str, lr: IntRange, rr: IntRange) -> Optional[int]:
    """The constant truth value (1 / 0) of ``lr OP rr`` when the operand
    ranges prove it, else ``None``. Only ever returns a value when the
    intervals are disjoint or fully ordered."""
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
        # Structured anchor for machine output; mirrors the Location in pretty().
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

    def _describe(self, cond) -> str:
        """A short human label for the condition: ``lhs OP rhs`` when it is
        a comparison, else the SSAVar's defining op / name."""
        d = getattr(cond, "defined_by", None)
        if d is not None and d.op in _CMP and len(d.inputs) == 2:
            lhs, rhs = binary_operands(d)
            return f"{_label(lhs)} {d.op} {_label(rhs)}"
        return _label(cond)

    def _cond_const(self, cond) -> Optional[int]:
        """1 if ``cond`` is provably non-zero (true), 0 if provably zero
        (false), else ``None``. A comparison is evaluated from its operand
        ranges; any other value from its own range.

        Pure-constant conditions (both comparison operands literal, or a
        bare literal condition) are skipped: ``assert(1)`` / ``0 < 1`` /
        ``int 0; bnz`` are compiler-emitted constant folding, not a guard
        that *looks* like it constrains a runtime value but doesn't. A
        finding therefore always involves at least one non-constant value
        (a field read, input, or computed result)."""
        d = getattr(cond, "defined_by", None)
        if d is not None and d.op in _CMP and len(d.inputs) == 2:
            lhs, rhs = binary_operands(d)
            if is_const(lhs) and is_const(rhs):
                return None
            lr = _operand_range(lhs)
            rr = _operand_range(rhs)
            if lr is not None and rr is not None:
                return _eval_cmp(d.op, lr, rr)
            return None
        if is_const(cond):
            return None
        r = _operand_range(cond)
        if r is not None:
            if r.lo >= 1:
                return 1
            if r.lo == 0 and r.hi == 0:
                return 0
        return None

    def detect(self) -> list[ConstantConditionViolation]:
        prog = self.prog
        # PRECONDITION: the ranges must be value FACTS, not assert-refined ones
        # (see the module docstring). Assert refinement is irreversible on a
        # shared program, so decline rather than report every asserted
        # comparison as vacuous.
        if getattr(prog, "_assert_ranges_applied", False):
            logger.warning(
                "constant-condition skipped: propagate_assert_ranges has "
                "already refined this program's ranges USING its asserts, so "
                "every asserted comparison would read as vacuous. Run this "
                "detector on a freshly built SSAProgram.")
            return []
        # Value-fact ranges only (NOT assert-refinement — see module docs).
        prog.propagate_constants()
        prog.propagate_range_arithmetic()  # lazy-trips propagate_ranges

        out: list[ConstantConditionViolation] = []
        for a in prog.assignments:
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


def _label(operand) -> str:
    """Best-effort short label for an operand in a finding message."""
    d = getattr(operand, "defined_by", None)
    if d is not None and d.op in ("txn", "gtxn", "gtxns", "itxn", "global"):
        return d.immediates or d.op
    cv = getattr(operand, "const_value", None)
    if cv is not None:
        return getattr(cv, "value", str(cv))
    from tealql.tealtools.ssa import Const
    if isinstance(operand, Const):
        return getattr(operand, "value", str(operand))
    return str(operand)
