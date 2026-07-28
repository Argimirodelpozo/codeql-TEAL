"""Suppress taint violations whose sink operand a path predicate has PINNED.

HAZARD: suppression must require pinning the VALUE, never merely mentioning it.
``assert(len(arg) == 4)`` mentions ``arg`` and shares its taint chain, but the
attacker still picks all four bytes — treating that as validation hides a real
finding. Only an equality tying the operand itself to a clean value counts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .engine import Violation
from ..path_predicates import BranchCondition, PathPredicateAnalysis
from ..ssa import SSAProgram


@dataclass(frozen=True)
class SuppressedViolation:
    """A taint violation a path predicate vouched for."""

    violation: Violation
    validated_by: BranchCondition

    def pretty(self) -> str:
        return (
            f"{self.violation.pretty()}  "
            f"(validated by {self.validated_by!r})"
        )

    def to_dict(self) -> dict:
        return {
            "violation": self.violation.to_dict(),
            "validated_by": repr(self.validated_by),
        }


def _taint_chain(operand, depth: int = 6) -> list:
    """Every operand upstream of ``operand``, via ``defined_by`` and phi args.

    Phi args must be walked — a phi has no ``defined_by``, so without them a
    sink operand reached through a join never connects to its sources. Depth is
    capped against cyclic phis; a list because operands may not be hashable."""
    out: list = [operand]
    seen_ids: set[int] = {id(operand)}
    stack: list[tuple[object, int]] = [(operand, depth)]
    while stack:
        op, d = stack.pop()
        if op is None or d == 0:
            continue
        next_ops: list = []
        a = getattr(op, "defined_by", None)
        if a is not None:
            next_ops.extend(a.inputs)
        # Phi-style merge: walk back through every arg.
        args = getattr(op, "args", None)
        if args is not None:
            next_ops.extend(args)
        for inp in next_ops:
            if inp is None or id(inp) in seen_ids:
                continue
            seen_ids.add(id(inp))
            out.append(inp)
            stack.append((inp, d - 1))
    return out


def _same_value_set(operand, depth: int = 8) -> list:
    """Every operand that IS ``operand``, over stack-shuffle identity edges.

    HAZARD: much narrower than :func:`_taint_chain` on purpose — ``len(X)`` is in
    X's taint chain but is NOT X, and pinning a derived property does not pin the
    value. Identity comes from the exact ``output_index -> input_index``
    permutation, so ``dup``'s outputs link but ``swap``'s stay DISTINCT; a
    blanket "same op" rule would equate the two halves of a swap. Phis are not
    traversed (``phi(a, b)`` equals ``a`` on one edge only), which costs a
    possible extra report but never soundness."""
    from ..ssa.ssa import _shuffle_mapping

    out: list = [operand]
    seen: set[int] = {id(operand)}
    stack: list[tuple[object, int]] = [(operand, depth)]

    def _link(v, d):
        """Neighbours of ``v`` across one shuffle, in both directions."""
        res: list = []
        a = getattr(v, "defined_by", None)
        if a is None:
            return res
        m = _shuffle_mapping(a)
        if m is None:
            return res
        # backward: this output came from a specific input
        for oi, o in enumerate(a.outputs):
            if o is v and oi < len(m) and m[oi] < len(a.inputs):
                src = a.inputs[m[oi]]
                res.append(src)
                # forward: every OTHER output fed by that same input is a copy
                for oj, o2 in enumerate(m):
                    if oj != oi and o2 == m[oi] and oj < len(a.outputs):
                        res.append(a.outputs[oj])
        return res

    # Forward from an input into the outputs it feeds.
    def _forward(v):
        res: list = []
        for use in getattr(v, "uses", ()) or ():
            m = _shuffle_mapping(use)
            if m is None:
                continue
            for oi, in_i in enumerate(m):
                if in_i < len(use.inputs) and use.inputs[in_i] is v \
                        and oi < len(use.outputs):
                    res.append(use.outputs[oi])
        return res

    while stack:
        v, d = stack.pop()
        if v is None or d == 0:
            continue
        for nb in (*_link(v, d), *_forward(v)):
            if nb is None or id(nb) in seen:
                continue
            seen.add(id(nb))
            out.append(nb)
            stack.append((nb, d - 1))
    return out


def _equality_operands(pred: BranchCondition):
    """``(lhs, rhs)`` of the equality this predicate asserts, or ``None``.

    Both shapes count: a ``kind="eq"`` predicate, and a boolean predicate on an
    ``==`` result — or on ``zero`` of a ``!=``, which is its complement."""
    from ..ssa.operands import binary_operands

    if pred.kind == "eq" and pred.args:
        return pred.value, pred.args[0]
    d = getattr(pred.value, "defined_by", None)
    if d is None or len(d.inputs) != 2:
        return None
    if (pred.kind == "nonzero" and d.op in ("==", "b==")) or \
       (pred.kind == "zero" and d.op in ("!=", "b!=")):
        return binary_operands(d)
    return None


def _pins_operand(pred: BranchCondition, operand) -> bool:
    """True iff ``pred`` pins ``operand`` ITSELF to an attacker-independent value."""
    from .byte_taint import _is_clean

    pair = _equality_operands(pred)
    if pair is None:
        return False
    same = {id(v) for v in _same_value_set(operand)}
    lhs, rhs = pair
    for a, b in ((lhs, rhs), (rhs, lhs)):
        if id(a) in same and _is_clean(b):
            return True
    return False


def _validating_predicate(
    operand,
    file: str,
    line: int,
    pp: PathPredicateAnalysis,
) -> Optional[BranchCondition]:
    """The predicate at ``(file, line)`` that pins ``operand``, if any."""
    # ``predicates_at`` returns a frozenset whose order is hash-seed-dependent;
    # sort so the reported predicate is deterministic when several match.
    preds = sorted(pp.predicates_at(file, line), key=repr)
    for p in preds:
        if _pins_operand(p, operand):
            return p
    return None


def filter_validated(
    violations: Iterable[Violation],
    prog: SSAProgram,
    *,
    pp: Optional[PathPredicateAnalysis] = None,
) -> tuple[list[Violation], list[SuppressedViolation]]:
    """Partition ``violations`` into ``(remaining, suppressed)`` by sink pinning."""
    pp = pp or PathPredicateAnalysis(prog)
    remaining: list[Violation] = []
    suppressed: list[SuppressedViolation] = []
    for v in violations:
        sink_op = v.sink_operand
        loc = v.sink.location
        match = _validating_predicate(sink_op, loc.file, loc.line, pp)
        if match is None:
            remaining.append(v)
        else:
            suppressed.append(SuppressedViolation(violation=v, validated_by=match))
    return remaining, suppressed
