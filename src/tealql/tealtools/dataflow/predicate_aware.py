"""Predicate-aware filtering of taint violations.

Wraps any taint detector that emits :class:`tealql.tealtools.dataflow.Violation`
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


def _same_value_set(operand, depth: int = 8) -> list:
    """Every operand that IS ``operand`` (the same runtime value), following
    stack-shuffle identity edges in BOTH directions.

    Deliberately much narrower than :func:`_taint_chain`, which walks every
    upstream input: ``len(X)`` has ``X`` in its taint chain but is NOT the same
    value as ``X``, and pinning a derived property does not pin the value.

    Identity comes from :func:`_shuffle_mapping`, which gives the exact
    ``output_index -> input_index`` permutation, so ``dup``'s two outputs are
    both linked to their shared input (and to each other, transitively) while
    ``swap``'s two outputs stay correctly DISTINCT. A blanket "same op" rule
    would wrongly equate the two halves of a swap.

    Phis are NOT traversed: ``phi(a, b)`` equals ``a`` only on one incoming
    edge, so a guard pinning ``a`` does not pin the phi. Stopping here costs
    precision (a possible extra report), never soundness."""
    from ..ssa.ssa import _shuffle_mapping

    # Build the identity edges lazily from the defining assignments we meet.
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

    # Also walk forward from an input into the outputs it feeds. Collect the
    # candidate assignments once from the operand's own uses.
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

    Recognises the two shapes an equality reaches us in: a ``kind="eq"``
    predicate carrying its literal in ``args``, and a boolean predicate on the
    result of an ``==`` op (or ``zero`` on a ``!=``, its complement)."""
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
    """True iff ``pred`` constrains ``operand`` ITSELF to an attacker-
    independent value.

    A predicate that merely MENTIONS the operand does not sanitise it: after
    ``assert(len(arg) == 4)`` the attacker still chooses all four bytes, so
    suppressing the ``box_put(arg)`` flow on that basis hides a real finding.
    Require an equality that pins the whole value against a clean operand."""
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
    """A predicate validates the sink operand only if it PINS that value to
    something attacker-independent.

    Example that validates: ``assert(arg == "allowed"); ... box_put(arg)`` —
    the equality ties ``arg`` itself to a constant.

    Example that does NOT: ``assert(len(arg) == 4); ... box_put(arg)``. The
    guard mentions ``arg`` and their taint chains intersect, but the attacker
    still chooses every byte, so treating it as validation SUPPRESSED a real
    finding. Chain intersection alone is not sanitisation.
    """
    # ``predicates_at`` returns a frozenset; its iteration order is
    # hash-seed-dependent. Sort by repr so that when several predicates
    # validate the same operand the *reported* one is deterministic.
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
    """Partition ``violations`` into ``(remaining, suppressed)``.

    A violation is suppressed iff some :class:`BranchCondition` at the sink BB
    PINS the sink operand to an attacker-independent value (see
    :func:`_pins_operand`) — not merely mentions it.
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
