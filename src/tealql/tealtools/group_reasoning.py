"""Identify the group shape(s) a TEAL contract forces.

A contract runs inside an atomic group of up to 16 txns and inspects it via
``gtxn[i].field`` / ``gtxns field`` / ``Global.GroupSize`` / ``Txn.GroupIndex``.
Any ``assert`` or branch on those values FORCES the group to satisfy that
constraint on every approving execution — the contract rejects otherwise. This
module rebuilds those path predicates as semantic constraints
(``Global.GroupSize == 2``, ``gtxn[0].TypeEnum == pay``, …).

Three views, coarse to fine: :func:`analyze` (common shape),
:func:`analyze_per_exit` (distinct admissible shapes, ABI-labelled),
:func:`constraints_at` / :func:`per_block_constraints` (per-block substrate).

HAZARD: :func:`analyze` INTERSECTS across approving exits, so a contract
admitting several shapes (``GroupSize==2`` on one arm, ``==3`` on another)
reports only what they share — often nothing. An empty result means "no COMMON
constraint", never "unconstrained"; use :func:`analyze_per_exit` for the per-arm
truth. Per-exit is itself a meet over the paths reaching one exit, so shapes
that merge before a single ``return`` are still not split.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .path_predicates import BranchCondition, PathPredicateAnalysis
from .ssa import Const, SSAProgram, SSAVar, binary_operands, const_int as _const_int
from .avm import U64_CMP_OPS, enum_field_name


# Comparison ops whose result is the boolean we end up asserting / branching on.
_CMP_OPS = U64_CMP_OPS


@dataclass(frozen=True)
class GroupRef:
    """A reference into the group context.

    ``slot`` ∈ ``{"global", "this", "gtxn[N]"}`` for ``Global.X`` / ``Txn.X`` /
    direct ``gtxn N field``. Stack-indexed ``gtxns`` is not classified here —
    see :func:`relative_slot`.
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
    """The :class:`GroupRef` for an SSAVar produced DIRECTLY by ``gtxn`` /
    ``txn`` / ``global``, else ``None`` — phis and arithmetic are not followed,
    so a value joined from several refs stays conservatively unclassified.
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


# ---------------------------------------------------------------------------
# Relative-index group members + per-member array sizing
#
# ``gtxns F`` whose popped index is ``Txn.GroupIndex ± k`` forces a member at
# that offset on every approving run, and ``gtxnsa/txna/gtxna F i`` forces the
# addressed member to carry enough ``F`` elements or the read panics.
# :func:`classify` models neither; the helpers below recover them ADDITIVELY.
# ---------------------------------------------------------------------------


def _is_group_index(operand: object) -> bool:
    """True when ``operand`` is produced directly by ``txn GroupIndex``."""
    a = getattr(operand, "defined_by", None)
    return a is not None and a.op == "txn" and a.immediates.strip() == "GroupIndex"


def relative_slot(idx_operand: object) -> Optional[str]:
    """The group slot a ``gtxns``/``gtxnsa`` stack index addresses: ``"this"``,
    ``"this-k"`` / ``"this+k"`` for a ``GroupIndex ∓ k`` sibling, or
    ``"gtxn[N]"``; ``None`` if the index isn't a static group position.

    HAZARD: a binary op's ``inputs`` are TOP-FIRST — ``[top_of_stack, deeper]``
    with value ``deeper OP top``, so ``txn GroupIndex; intc_1; -`` has
    ``inputs=[1, GroupIndex]`` and means ``GroupIndex - 1``. Run
    ``propagate_scratch_values()`` first so a stored ``GroupIndex-1`` forwards.
    """
    k = _const_int(idx_operand)
    if k is not None:
        return f"gtxn[{k}]"
    if _is_group_index(idx_operand):
        return "this"
    a = getattr(idx_operand, "defined_by", None)
    if a is None or a.op not in ("+", "-") or len(a.inputs) != 2:
        return None
    top, deeper = a.inputs[0], a.inputs[1]
    # value = deeper OP top; a group-relative index is GroupIndex +/- const.
    if _is_group_index(deeper):
        kc = _const_int(top)
        if kc is not None:
            if kc == 0:
                return "this"
            return f"this+{kc}" if a.op == "+" else f"this-{kc}"
    if a.op == "+" and _is_group_index(top):        # commute: const + GroupIndex
        kc = _const_int(deeper)
        if kc is not None:
            return "this" if kc == 0 else f"this+{kc}"
    return None


# Array field -> (Num-field, bump). HAZARD: the bump is NOT uniform —
# ApplicationArgs/Assets panic at `i >= NumX` (need NumX >= i+1), but
# Accounts/Applications carry an implicit element 0 (Sender / current app) and
# panic at `i > NumX` (need NumX >= i).
_ARRAY_FIELD_NUM = {
    "ApplicationArgs": ("NumAppArgs", 1),
    "Assets": ("NumAssets", 1),
    "Accounts": ("NumAccounts", 0),
    "Applications": ("NumApplications", 0),
}


def array_counts(prog: SSAProgram) -> dict[str, dict[str, int]]:
    """Minimum array-element counts a contract's ``gtxnsa``/``gtxna``/``txna``
    reads force per group slot: ``{slot: {NumField: min_count}}``.

    A member addressed by ``F i`` must carry at least ``min_count`` ``F``
    elements or the read panics and the accepting path is unreachable. Slots are
    :func:`relative_slot` strings; run ``propagate_scratch_values()`` on ``prog``
    first for relative indices.
    """
    out: dict[str, dict[str, int]] = {}
    for a in prog:
        if a.op == "txna":
            slot, imm = "this", a.immediates
        elif a.op == "gtxna":
            parts = a.immediates.split()          # "N F i"
            if len(parts) < 3:
                continue
            slot, imm = f"gtxn[{parts[0]}]", f"{parts[1]} {parts[2]}"
        elif a.op == "gtxnsa":
            slot = relative_slot(a.inputs[0]) if a.inputs else None
            imm = a.immediates                    # "F i"
        else:
            continue
        if slot is None:
            continue
        toks = imm.split()
        if len(toks) < 2:
            continue
        field = toks[0]
        try:
            idx = int(toks[1])
        except ValueError:
            continue
        num = _ARRAY_FIELD_NUM.get(field)
        if num is None:
            continue
        num_field, bump = num
        need = idx + bump
        slot_m = out.setdefault(slot, {})
        slot_m[num_field] = max(slot_m.get(num_field, 0), need)
    return out


@dataclass(frozen=True)
class GroupConstraint:
    """One constraint a contract forces: ``ref op rhs``, where ``rhs`` is a
    :class:`Const`, another :class:`GroupRef`, or an unresolved operand
    (rendered with a ``?`` prefix).
    """

    ref: GroupRef
    op: str
    rhs: object

    def render(self) -> str:
        return f"{self.ref!r} {self.op} {_render_rhs(self.rhs, self.ref.field)}"

    def to_dict(self) -> dict:
        return {"ref": repr(self.ref), "op": self.op,
                "rhs": _render_rhs(self.rhs, self.ref.field)}


def _render_rhs(rhs: object, field: Optional[str] = None) -> str:
    val = None
    if isinstance(rhs, Const):
        val = rhs.value
    else:
        cv = getattr(rhs, "const_value", None)
        if cv is not None and isinstance(cv, Const):
            val = cv.value
    if val is not None:
        if field is not None:                     # render the enum: TypeEnum==1 -> `pay`
            try:
                name = enum_field_name(field, int(val))
            except (ValueError, TypeError):
                name = None
            if name is not None:
                return name
        return val
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


#: :class:`BranchCondition` kind -> comparator, for predicates constraining a
#: group ref DIRECTLY — switch / match targets and ordered compares driving a
#: branch, where there is no comparison op to recover the operator from.
_KIND_TO_OP = {
    "eq": "==", "neq": "!=",
    "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
}


def derive_constraint(pred: BranchCondition) -> Optional[GroupConstraint]:
    """Translate a path predicate into a group-shape constraint, else ``None``.

    Either ``pred.value`` IS a group ref (a direct branch/assert on it, rendered
    against literal ``0``), or it is the result of a comparison whose operands
    include one and the comparator is recovered from that op.

    HAZARD: ``pred.kind == "zero"`` means the comparison was FALSE on every
    approving path, so the recovered comparator MUST be negated. Skipping the
    negation records the opposite of what the contract enforces.
    """
    direct = classify(pred.value)
    if direct is not None:
        # Direct: value was branched/asserted as nonzero (or zero).
        if pred.kind == "nonzero":
            return GroupConstraint(direct, "!=", Const("int", "0"))
        if pred.kind == "zero":
            return GroupConstraint(direct, "==", Const("int", "0"))
        # A group ref routed by switch / match / an ordered compare — the PuyaPy
        # router idiom (``txn OnCompletion; switch …``).
        if pred.kind in _KIND_TO_OP and len(pred.args) >= 1:
            return GroupConstraint(direct, _KIND_TO_OP[pred.kind], pred.args[0])
        if pred.kind == "not_in_range" and len(pred.args) >= 2:
            # value ∉ [lo .. hi-1]: the only faithful single-comparator
            # rendering is against the exclusive upper bound.
            return GroupConstraint(direct, ">=", pred.args[1])
        # ``neq_all`` is a conjunction of != over N candidates that one
        # GroupConstraint cannot express — emit nothing rather than one
        # arbitrary disjunct posing as the whole fact.
        return None
    if not isinstance(pred.value, SSAVar):
        return None
    a = getattr(pred.value, "defined_by", None)
    if a is None or a.op not in _CMP_OPS or len(a.inputs) < 2:
        return None
    # HAZARD: operands are TOP-FIRST — the SOURCE-order comparison is
    # ``inputs[1] OP inputs[0]``, so a non-commutative relation (``>=`` / ``<``
    # …) inverts if read positionally. Always go through ``binary_operands``.
    lhs, rhs = binary_operands(a)
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
        return None  # eq-of-cmp-result etc. — not modelled.
    return GroupConstraint(ref=ref, op=op, rhs=other)  # type: ignore[arg-type]


@dataclass
class GroupShape:
    """The group-shape constraints a program forces on every approving exit."""

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
    """The group shape ``prog`` forces on EVERY approving path (their intersection)."""
    pp = pp or PathPredicateAnalysis(prog)
    return GroupShape(constraints=_constraints_from(pp.approving_exit_summary()))


def _constraints_from(preds) -> list[GroupConstraint]:
    """Distinct group constraints derivable from a predicate set, dedup order-preserving."""
    out: list[GroupConstraint] = []
    seen: set[GroupConstraint] = set()
    for pred in preds:
        c = derive_constraint(pred)
        if c is not None and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def constraints_at(pp: PathPredicateAnalysis, bb) -> list[GroupConstraint]:
    """Group constraints IN FORCE at ``bb`` — the meet over every path reaching
    it, so a flow-sensitive consumer can ask what holds at an arbitrary point."""
    return _constraints_from(pp.bb_preds.get(bb, frozenset()))


def per_block_constraints(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> dict:
    """``{BasicBlock: [GroupConstraint, ...]}`` for every block that has any."""
    pp = pp or PathPredicateAnalysis(prog)
    out = {}
    for bb in prog.blocks.values():
        cs = constraints_at(pp, bb)
        if cs:
            out[bb] = cs
    return out


@dataclass
class ExitShape:
    """The shape forced on the paths reaching one approving exit — or the set of
    exits forcing the IDENTICAL shape. ``exits`` is ``(line, method)`` pairs,
    ``method`` being ``None`` when no source ABI info is available."""

    shape: GroupShape
    exits: list          # list[tuple[int, Optional[str]]]

    def _tag(self) -> str:
        return ", ".join((f"{m}@L{ln}" if m else f"L{ln}") for ln, m in self.exits)

    def render(self) -> str:
        body = self.shape.render()
        indented = "\n".join("    " + ln for ln in body.splitlines())
        return f"[{self._tag()}]\n{indented}"

    def to_dict(self) -> dict:
        return {
            "exits": [{"line": ln, "method": m} for ln, m in self.exits],
            **self.shape.to_dict(),
        }


@dataclass
class PerExitShapes:
    """All distinct per-exit group shapes a program admits."""

    shapes: list         # list[ExitShape]

    def render(self) -> str:
        if not self.shapes:
            return "(no approving exits)"
        return "\n".join(s.render() for s in self.shapes)

    def to_dict(self) -> dict:
        return {"exit_shapes": [s.to_dict() for s in self.shapes]}


def exit_method_lookup(prog):
    """A ``bb -> ABI method name | None`` resolver over source ``method "sig"``
    info, cached per file.

    HAZARD: ``bb.file`` is a BASENAME and must be resolved back to a real path
    through ``prog.source_path``. Fully defensive — any failure yields ``None``;
    this is OPTIONAL labelling, never a fact analysis may depend on."""
    from pathlib import Path
    from .abi import method_line_ranges, method_at_line

    src = Path(str(getattr(prog, "source_path", "") or ""))
    by_name: dict = {}
    try:
        if src.is_dir():
            for p in src.rglob("*.teal"):
                by_name.setdefault(p.name, p)
        elif src.exists():
            by_name[src.name] = src
    except Exception:
        by_name = {}

    cache: dict = {}

    def _ranges(fname):
        if fname not in cache:
            p = by_name.get(fname) or by_name.get(Path(fname).name)
            try:
                cache[fname] = method_line_ranges(p.read_text(errors="ignore")) if p else []
            except Exception:
                cache[fname] = []
        return cache[fname]

    def _lookup(bb):
        f = getattr(bb, "file", None)
        if not f:
            return None
        m = method_at_line(_ranges(f), getattr(bb, "last_line", None))
        return m.name if m is not None else None

    return _lookup


def analyze_per_exit(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> PerExitShapes:
    """The DISTINCT group shapes a contract admits — one per approving exit
    (identical shapes merged, ABI-labelled), rather than :func:`analyze`'s
    intersection. Still a meet over the paths reaching each exit, so shapes that
    merge before a single ``return`` are not split."""
    pp = pp or PathPredicateAnalysis(prog)
    method_of = exit_method_lookup(prog)
    groups: dict = {}     # shape-key -> [GroupShape, exits]
    order: list = []
    for bb in sorted(pp.approving_exits(),
                     key=lambda b: (b.file, b.first_line)):
        cs = constraints_at(pp, bb)
        key = frozenset(c.render() for c in cs)
        line = getattr(bb, "last_line", None) or getattr(bb, "first_line", 0)
        entry = groups.get(key)
        if entry is None:
            groups[key] = [GroupShape(cs), [(line, method_of(bb))]]
            order.append(key)
        else:
            entry[1].append((line, method_of(bb)))
    return PerExitShapes(shapes=[
        ExitShape(shape=groups[k][0], exits=groups[k][1]) for k in order
    ])


# --- Group size + layout report: presentation over GroupShape --------------


def _gtxn_index(ref: GroupRef) -> Optional[int]:
    """The absolute group index ``ref`` pins, if it's a ``gtxn[N]`` slot."""
    if ref.slot.startswith("gtxn[") and ref.slot.endswith("]"):
        try:
            return int(ref.slot[5:-1])
        except ValueError:
            return None
    return None


@dataclass
class GroupLayout:
    """A size + per-position view of :func:`analyze`'s constraints, bucketed by
    the slot each pins: ``Global.GroupSize`` → group size, ``Txn.GroupIndex`` →
    this app's position, ``gtxn[N].field`` → position ``N`` (either operand, so
    a slot's requirements read together), the rest → "this txn" / "globals".
    """

    file: str
    constraints: list[GroupConstraint]

    def _buckets(self):
        size: list[GroupConstraint] = []
        index: list[GroupConstraint] = []
        positions: dict[int, list[tuple[str, str, str]]] = {}
        this_fields: list[GroupConstraint] = []
        globals_: list[GroupConstraint] = []
        for c in self.constraints:
            ref, rhs = c.ref, c.rhs
            if ref.slot == "global" and ref.field == "GroupSize":
                size.append(c)
                continue
            if ref.slot == "this" and ref.field == "GroupIndex":
                index.append(c)
                continue
            # Prefer a gtxn slot on either side so a slot's requirements group.
            lhs_i = _gtxn_index(ref)
            rhs_ref = classify(rhs)
            rhs_i = _gtxn_index(rhs_ref) if rhs_ref is not None else None
            if lhs_i is not None:
                positions.setdefault(lhs_i, []).append(
                    (ref.field, c.op, _render_rhs(rhs, ref.field))
                )
            elif rhs_i is not None:
                # The slot is on the RHS here, so the comparator must be
                # flipped when the slot field is moved to the left.
                positions.setdefault(rhs_i, []).append(
                    (rhs_ref.field, _flip(c.op), repr(ref))
                )
            elif ref.slot == "this":
                this_fields.append(c)
            else:
                globals_.append(c)
        return size, index, positions, this_fields, globals_

    def render(self) -> str:
        if not self.constraints:
            return f"=== Group layout  {self.file} ===\n  (no group-shape constraints)"
        size, index, positions, this_fields, globals_ = self._buckets()
        out = [f"=== Group layout  {self.file} ==="]
        if size:
            out.append("  group size : " + ", ".join(
                f"{c.op} {_render_rhs(c.rhs)}" for c in size
            ))
        else:
            out.append("  group size : (unconstrained)")
        if index:
            out.append("  this txn   : GroupIndex " + ", ".join(
                f"{c.op} {_render_rhs(c.rhs)}" for c in index
            ))
        for i in sorted(positions):
            out.append(f"  gtxn[{i}]:")
            for fld, op, rhs in sorted(set(positions[i])):
                out.append(f"      {fld} {op} {rhs}")
        if this_fields:
            out.append("  this txn fields:")
            for c in sorted(this_fields, key=_constraint_sort_key):
                out.append(f"      {c.ref.field} {c.op} {_render_rhs(c.rhs)}")
        if globals_:
            out.append("  globals:")
            for c in sorted(globals_, key=_constraint_sort_key):
                out.append(f"      {c.ref.field} {c.op} {_render_rhs(c.rhs)}")
        return "\n".join(out)

    def print(self) -> None:
        print(self.render())

    def to_dict(self) -> dict:
        size, index, positions, this_fields, globals_ = self._buckets()
        return {
            "file": self.file,
            "group_size": [f"{c.op} {_render_rhs(c.rhs)}" for c in size],
            "this_index": [f"{c.op} {_render_rhs(c.rhs)}" for c in index],
            "positions": {
                str(i): [f"{fld} {op} {rhs}" for fld, op, rhs in sorted(set(positions[i]))]
                for i in sorted(positions)
            },
            "this_txn_fields": [
                f"{c.ref.field} {c.op} {_render_rhs(c.rhs, c.ref.field)}"
                for c in sorted(this_fields, key=_constraint_sort_key)
            ],
            "globals": [
                f"{c.ref.field} {c.op} {_render_rhs(c.rhs, c.ref.field)}"
                for c in sorted(globals_, key=_constraint_sort_key)
            ],
        }


def analyze_layout(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> GroupLayout:
    """:func:`analyze`'s forced shape, presented as a :class:`GroupLayout`."""
    pp = pp or PathPredicateAnalysis(prog)
    shape = analyze(prog, pp)
    files = sorted({bb.file for bb in pp.approving_exits()})
    if len(files) == 1:
        file = files[0]
    elif files:
        file = ", ".join(files)
    else:
        file = "(no approving exits)"
    return GroupLayout(file=file, constraints=shape.constraints)
