"""Opcode-cost facts over the canonical AVM instruction stream."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..ssa import Assignment, BasicBlock


@dataclass(frozen=True)
class CostFact:
    """A cost interval plus the evidence quality behind it.

    ``upper=None`` means the available language specification does not provide
    a finite static upper bound.  ``lower`` remains useful: shortest paths and
    loop iteration ceilings need a cost lower bound, and one is the AVM opcode
    floor.  Such a result is deliberately marked non-exact.
    """

    lower: int
    upper: Optional[int]
    exact: bool
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.lower < 0:
            raise ValueError("cost lower bound must be non-negative")
        if self.upper is not None and self.upper < self.lower:
            raise ValueError("cost upper bound is below lower bound")
        if self.exact != (self.upper is not None and self.lower == self.upper):
            raise ValueError("exact must agree with a singleton interval")

    @classmethod
    def known(cls, cost: int) -> "CostFact":
        return cls(cost, cost, True)

    @classmethod
    def unknown(cls, reason: str, *, lower: int = 1) -> "CostFact":
        return cls(lower, None, False, (reason,))

    def __add__(self, other: "CostFact") -> "CostFact":
        upper = None if self.upper is None or other.upper is None else self.upper + other.upper
        reasons = tuple(dict.fromkeys((*self.reasons, *other.reasons)))
        return CostFact(
            self.lower + other.lower,
            upper,
            upper is not None and self.lower + other.lower == upper,
            reasons,
        )

    def scale(self, count: int) -> "CostFact":
        if count < 0:
            raise ValueError("cost multiplier must be non-negative")
        upper = None if self.upper is None else self.upper * count
        return CostFact(
            self.lower * count,
            upper,
            upper is not None and self.lower * count == upper,
            self.reasons,
        )

    @property
    def degraded(self) -> bool:
        return not self.exact


@dataclass(frozen=True)
class _CostTable:
    fixed: dict[str, int]
    dynamic: frozenset[str]
    available: bool


@lru_cache(maxsize=1)
def _puya_cost_table() -> _CostTable:
    try:
        from puya.ir.avm_ops import AVMOp
    except Exception:
        return _CostTable({}, frozenset(), False)
    fixed: dict[str, int] = {}
    dynamic: set[str] = set()
    for member in AVMOp:
        raw = getattr(member, "cost", None)
        if isinstance(raw, int):
            fixed[member.code] = raw
        else:
            dynamic.add(member.code)
    return _CostTable(fixed, frozenset(dynamic), True)


def op_cost(op: str, immediates: str = "") -> CostFact:
    """Cost of one opcode execution, without pretending dynamic costs are exact."""
    table = _puya_cost_table()
    fixed = table.fixed.get(op)
    if fixed is not None:
        return CostFact.known(fixed)
    suffix = f" {immediates.strip()}" if immediates and immediates.strip() else ""
    if not table.available:
        return CostFact.unknown("Puya cost metadata unavailable")
    if op in table.dynamic:
        return CostFact.unknown(f"dynamic cost for {op}{suffix}")
    # Source-level pseudo ops (``int``) and control terminators are lowered
    # away before Puya IR, so they do not occur in AVMOp even though their AVM
    # execution cost is the fixed floor.
    from ..language.avm import is_known_op
    if is_known_op(op):
        return CostFact.known(1)
    return CostFact.unknown(f"unknown opcode cost for {op}{suffix}")


def sum_costs(facts: Iterable[CostFact]) -> CostFact:
    total = CostFact.known(0)
    for fact in facts:
        total = total + fact
    return total


def canonical_assignments(bb: "BasicBlock") -> tuple["Assignment", ...]:
    """The opcodes the AVM executes, independent of presentation cleanup."""
    stream = bb.stack_assignments
    return tuple(stream) if stream else tuple(bb.assignments)


def assignment_cost(assignment: "Assignment") -> CostFact:
    return op_cost(assignment.op, assignment.immediates or "")


def block_cost(bb: "BasicBlock") -> CostFact:
    return sum_costs(assignment_cost(a) for a in canonical_assignments(bb))


def block_stack_delta(bb: "BasicBlock") -> Optional[int]:
    """Net stack delta, or ``None`` when the block crosses a call boundary.

    Canonical SSA records actual call arguments on ``callsub`` but return values
    at the callee's ``retsub``.  Treating either block in isolation would mix
    frames, so callers may only use stack bounds for call-free cycles.
    """
    assignments = canonical_assignments(bb)
    if any(a.op in {"callsub", "retsub"} for a in assignments):
        return None
    # SSA inputs/outputs describe what stack simulation RECOVERED.  In an
    # underflow or merge-refusal shape operands and dead outputs may be absent,
    # but the AVM still executes the opcode's language-specified stack effect.
    from ..language.avm import op_arity
    delta = 0
    for assignment in assignments:
        n_in, n_out = op_arity(assignment.op, assignment.immediates or "")
        delta += n_out - n_in
    return delta
