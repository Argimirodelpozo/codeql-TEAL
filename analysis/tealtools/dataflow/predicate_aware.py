"""Predicate-aware filtering of taint violations.

Wraps any taint detector that emits :class:`tealtools.dataflow.Violation`
records and consults :class:`PathPredicateAnalysis` at each sink. A flow
is suppressed when the sink operand — or any operand in its
backwards taint chain — is mentioned by a path predicate that
holds on every path to the sink.

What "mentioned" means here is intentionally coarse: any
:class:`BranchCondition` whose ``value`` or ``args`` references the
operand counts as validation. The analyst's ``assert`` is treated
as enough evidence that the value is constrained, even if we don't
inspect the predicate's content. A predicate-content-aware variant
(e.g. recognising ``V < 100`` as a bound and suppressing only flows
to sinks that need bounded inputs) is a future refinement.

Suppression preserves the original :class:`Violation` plus the
validating predicate, so triage can see what the analyst's check
looked like:

    remaining, suppressed = filter_validated(detect_into_box_flows(prog), prog)
    for s in suppressed:
        print(f"{s.violation.pretty()}  (validated by {s.validated_by!r})")
"""
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
    """Walk back from ``operand`` through ``defined_by`` chains and
    Phi merge args, returning every operand visited (including
    ``operand`` itself).

    Both walk directions matter: ``defined_by`` covers ordinary SSA
    assignments; ``args`` covers phis (BB-join merges) which don't
    have a ``defined_by`` of their own. Without phi traversal a
    sink operand reached via a join would never connect to its
    upstream sources.

    Bounded depth so cyclic phi structures don't blow up — beyond
    the cap we conservatively stop walking. Returns a list (not a
    set) because operands may not be hashable.
    """
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


def _predicate_mentions(pred: BranchCondition, operand) -> bool:
    if pred.value is operand:
        return True
    return any(arg is operand for arg in pred.args)


def _validating_predicate(
    operand,
    file: str,
    line: int,
    pp: PathPredicateAnalysis,
) -> Optional[BranchCondition]:
    """A predicate validates the sink operand if their backwards
    taint chains intersect — the analyst's ``assert`` typically
    fires on a comparison op whose input is upstream of the sink
    operand, so we have to walk both sides to meet in the middle.

    Example: ``assert(arg == "allowed"); ... box_put(arg)``. The
    predicate is on the ``==``-result; walking back from that
    result reaches ``arg``, which is in the sink's chain.
    """
    sink_chain_ids = {id(o) for o in _taint_chain(operand)}
    preds = pp.predicates_at(file, line)
    for p in preds:
        # Direct mention by value or args.
        if _predicate_mentions(p, operand):
            return p
        if id(p.value) in sink_chain_ids:
            return p
        if any(id(a) in sink_chain_ids for a in p.args):
            return p
        # Walk back from the predicate's value: the assert often fires
        # on a comparison op whose inputs include an upstream of the
        # sink operand.
        for upstream in _taint_chain(p.value):
            if id(upstream) in sink_chain_ids:
                return p
    return None


def filter_validated(
    violations: Iterable[Violation],
    prog: SSAProgram,
    *,
    pp: Optional[PathPredicateAnalysis] = None,
) -> tuple[list[Violation], list[SuppressedViolation]]:
    """Partition ``violations`` into ``(remaining, suppressed)``.

    A violation is suppressed iff some :class:`BranchCondition` at
    the sink BB references the sink operand or any operand upstream
    in its taint chain.
    """
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
