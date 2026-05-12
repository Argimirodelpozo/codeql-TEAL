"""Identify the group shape(s) a TEAL contract forces.

A TEAL contract executes inside an atomic group of up to 16 txns; it
can inspect siblings via ``gtxn[i].field`` / ``gtxns field`` and the
group itself via ``Global.GroupSize`` / ``Txn.GroupIndex``. Any
``assert`` or branch on those values *forces* the group to satisfy
that constraint on every approving execution — the contract rejects
otherwise.

This module walks :meth:`PathPredicateAnalysis.approving_exit_summary`
(the intersection of predicates over approving paths), pulls out the
predicates whose operands trace back to a group-related opcode, and
rebuilds them as semantic constraints (``Global.GroupSize == 2``,
``gtxn[0].Receiver == Global.CurrentApplicationAddress``, …).

Conservative: returns only the *common* shape across approving paths.
A contract that admits multiple shapes (e.g. ``GroupSize==2`` on one
arm and ``GroupSize==3`` on another) shows only what's true on every
approving path. Per-path enumeration is a follow-up.

The substrate (``tealtools.ssa``) is not modified — this module only
consumes ``SSAProgram`` and ``PathPredicateAnalysis``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .path_predicates import BranchCondition, PathPredicateAnalysis
from .ssa import Const, SSAProgram, SSAVar


# Comparison ops in TEAL whose result is the boolean we typically
# end up asserting / branching on.
_CMP_OPS = {"==", "!=", "<", ">", "<=", ">="}


@dataclass(frozen=True)
class GroupRef:
    """A reference into the group context.

    ``slot`` ∈ ``{"global", "this", "gtxn[N]"}`` — ``"global"`` for
    ``Global.X``, ``"this"`` for ``Txn.X``, ``"gtxn[N]"`` for direct
    ``gtxn N field``. ``gtxns`` (stack-popped index) is unmodelled
    in v1 — its ref slot would be ``"gtxn[?]"`` carrying a runtime
    operand.
    """

    slot: str
    field: str

    def __repr__(self) -> str:
        if self.slot == "global":
            return f"Global.{self.field}"
        if self.slot == "this":
            return f"Txn.{self.field}"
        return f"{self.slot}.{self.field}"


def classify(operand: object) -> Optional[GroupRef]:
    """If ``operand`` is an SSAVar produced directly by a
    group-related opcode (``gtxn``, ``txn``, ``global``), return the
    matching :class:`GroupRef`. Otherwise ``None``.

    Doesn't follow phis or arithmetic — a value joined from multiple
    refs is conservatively unclassified, since "what slot is this"
    has no single answer.
    """
    if not isinstance(operand, SSAVar):
        return None
    a = getattr(operand, "defined_by", None)
    if a is None:
        return None
    if a.op == "gtxn":
        parts = a.immediates.split()
        if len(parts) >= 2:
            return GroupRef(slot=f"gtxn[{parts[0]}]", field=parts[1])
        return None
    if a.op == "txn":
        return GroupRef(slot="this", field=a.immediates.strip())
    if a.op == "global":
        return GroupRef(slot="global", field=a.immediates.strip())
    return None


@dataclass(frozen=True)
class GroupConstraint:
    """One semantic constraint a contract forces on the group.

    ``ref`` is the constrained slot/field; ``op`` is one of ``==``,
    ``!=``, ``<``, ``>``, ``<=``, ``>=``; ``rhs`` is a :class:`Const`
    literal, another :class:`GroupRef`, or an unresolved operand
    (rendered with a ``?`` prefix).
    """

    ref: GroupRef
    op: str
    rhs: object

    def render(self) -> str:
        return f"{self.ref!r} {self.op} {_render_rhs(self.rhs)}"

    def to_dict(self) -> dict:
        return {"ref": repr(self.ref), "op": self.op, "rhs": _render_rhs(self.rhs)}


def _render_rhs(rhs: object) -> str:
    if isinstance(rhs, Const):
        return rhs.value
    cv = getattr(rhs, "const_value", None)
    if cv is not None and isinstance(cv, Const):
        return cv.value
    ref = classify(rhs)
    if ref is not None:
        return repr(ref)
    return f"?{rhs!r}"


def _flip(op: str) -> str:
    return {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)


def _negate(op: str) -> str:
    return {
        "==": "!=", "!=": "==",
        "<": ">=", ">=": "<", ">": "<=", "<=": ">",
    }.get(op, op)


def derive_constraint(pred: BranchCondition) -> Optional[GroupConstraint]:
    """Translate a path predicate into a group-shape constraint.

    Two cases:

    1. ``pred.value`` *is* a group ref (e.g. ``Txn.GroupIndex != 0``
       from a direct ``bnz`` on the value). Renders as a comparison
       to literal ``0``.
    2. ``pred.value`` is the result of a comparison op whose inputs
       include a group ref (the common ``assert(gtxn[0].X == ...)``
       case). The comparator is recovered from the op; if
       ``pred.kind == "zero"`` (i.e. the comparison was *false* on
       every approving path) the comparator is negated.

    Returns ``None`` if neither case applies.
    """
    direct = classify(pred.value)
    if direct is not None:
        # Direct: value was branched/asserted as nonzero (or zero).
        if pred.kind == "nonzero":
            return GroupConstraint(direct, "!=", Const("int", "0"))
        if pred.kind == "zero":
            return GroupConstraint(direct, "==", Const("int", "0"))
        return None  # eq / neq_all / not_in_range on a direct ref —
                    # fall through, render generically (TODO).
    if not isinstance(pred.value, SSAVar):
        return None
    a = getattr(pred.value, "defined_by", None)
    if a is None or a.op not in _CMP_OPS or len(a.inputs) < 2:
        return None
    lhs, rhs = a.inputs[0], a.inputs[1]
    lhs_ref = classify(lhs)
    rhs_ref = classify(rhs)
    if lhs_ref is None and rhs_ref is None:
        return None
    if lhs_ref is not None:
        ref, other, op = lhs_ref, rhs, a.op
    else:
        # Refs on rhs; flip comparator so ref is on the left.
        ref, other, op = rhs_ref, lhs, _flip(a.op)
    if pred.kind == "zero":
        # Comparison was false on every approving path → negate.
        op = _negate(op)
    elif pred.kind != "nonzero":
        return None  # eq-of-cmp-result etc. — uncommon, skip for v1.
    return GroupConstraint(ref=ref, op=op, rhs=other)  # type: ignore[arg-type]


@dataclass
class GroupShape:
    """All group-shape constraints a program forces on every
    approving exit, ready to render."""

    constraints: list[GroupConstraint]

    def render(self) -> str:
        if not self.constraints:
            return "(no group-shape constraints)"
        return "\n".join(c.render() for c in sorted(
            self.constraints, key=_constraint_sort_key
        ))

    def to_dict(self) -> dict:
        return {"constraints": [
            c.to_dict() for c in sorted(self.constraints, key=_constraint_sort_key)
        ]}


def _constraint_sort_key(c: GroupConstraint):
    r = c.ref
    if r.slot == "global":
        slot_k = (0, 0)
    elif r.slot == "this":
        slot_k = (1, 0)
    elif r.slot.startswith("gtxn["):
        try:
            slot_k = (2, int(r.slot[5:-1]))
        except ValueError:
            slot_k = (3, 0)
    else:
        slot_k = (4, 0)
    return (slot_k, r.field, c.op, _render_rhs(c.rhs))


def analyze(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> GroupShape:
    """Top-level entry: compute the forced group shape for ``prog``.

    Reuses an externally-built :class:`PathPredicateAnalysis` if
    provided (cheap to share when the caller is also doing other
    predicate-based analyses), or builds one from scratch.
    """
    pp = pp or PathPredicateAnalysis(prog)
    constraints: list[GroupConstraint] = []
    seen: set[GroupConstraint] = set()
    for pred in pp.approving_exit_summary():
        c = derive_constraint(pred)
        if c is None or c in seen:
            continue
        seen.add(c)
        constraints.append(c)
    return GroupShape(constraints=constraints)
