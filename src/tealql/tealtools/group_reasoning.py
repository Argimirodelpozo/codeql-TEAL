"""Identify the group shape(s) a TEAL contract forces.

A TEAL contract executes inside an atomic group of up to 16 txns; it
can inspect siblings via ``gtxn[i].field`` / ``gtxns field`` and the
group itself via ``Global.GroupSize`` / ``Txn.GroupIndex``. Any
``assert`` or branch on those values *forces* the group to satisfy
that constraint on every approving execution — the contract rejects
otherwise.

The module pulls out the predicates whose operands trace back to a group-related
opcode and rebuilds them as semantic constraints (``Global.GroupSize == 2``,
``gtxn[0].Receiver == Global.CurrentApplicationAddress``,
``gtxn[0].TypeEnum == pay``, …). It captures ANY comparison on a group field —
not just ``GroupSize`` but txn types, pinned params, and ranges alike.

Three views, coarse to fine:

* :func:`analyze` — the *common* shape: predicates true on EVERY approving path
  (the intersection, :meth:`PathPredicateAnalysis.approving_exit_summary`). A
  contract admitting several shapes (``GroupSize==2`` on one arm, ``==3`` on
  another) shows only what they share — often nothing.
* :func:`analyze_per_exit` — the DISTINCT admissible shapes, one per approving
  exit (deduped, and labelled with the ABI method the exit sits in). Recovers the
  per-arm shapes the common summary drops.
* :func:`constraints_at` / :func:`per_block_constraints` — the per-block
  substrate: the group facts in force at any program point (from ``bb_preds``),
  for a flow-sensitive consumer.

Per-exit is a meet over the paths reaching one exit, so two shapes that merge
*before* a single ``return`` still aren't split — that needs full per-path
enumeration (in practice distinct shapes reach distinct exits).

The substrate (``tealql.tealtools.ssa``) is not modified — this module only
consumes ``SSAProgram`` and ``PathPredicateAnalysis``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .path_predicates import BranchCondition, PathPredicateAnalysis
from .ssa import Const, SSAProgram, SSAVar, binary_operands, const_int as _const_int
from .avm import U64_CMP_OPS, enum_field_name


# Comparison ops in TEAL whose result is the boolean we typically
# end up asserting / branching on.
_CMP_OPS = U64_CMP_OPS


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


# ---------------------------------------------------------------------------
# Relative-index group members + per-member array sizing
#
# A contract that reads a sibling at a *relative* position -- ``gtxns F`` where
# the popped index is ``Txn.GroupIndex - 1`` (a preceding txn) or ``+ 1`` (a
# following one) -- forces a member at that offset on every approving run. And
# ``gtxnsa F i`` / ``txna F i`` / ``gtxna N F i`` force the addressed member to
# carry at least enough ``F`` elements, or the read panics. Both facts are pure
# static reads of the bytecode; :func:`classify` (v1) punts on the stack-index
# ``gtxns`` and emits no array sizing. The two helpers below recover them, kept
# ADDITIVE (separate from ``classify``/``analyze`` so existing snapshots are
# untouched) and consumed by the verifier's harness group setup.
# ---------------------------------------------------------------------------


def _is_group_index(operand: object) -> bool:
    """True when ``operand`` is produced directly by ``txn GroupIndex``."""
    a = getattr(operand, "defined_by", None)
    return a is not None and a.op == "txn" and a.immediates.strip() == "GroupIndex"


def relative_slot(idx_operand: object) -> Optional[str]:
    """The group slot a ``gtxns``/``gtxnsa`` stack index addresses, as a slot
    string: ``"this"`` (``Txn.GroupIndex``), ``"this-k"``/``"this+k"`` (a
    ``GroupIndex -/+ k`` sibling), or ``"gtxn[N]"`` (a constant index). ``None``
    when the index isn't a statically-recognised group position.

    Relies on the SSA convention (confirmed on the substrate): a binary op's
    ``inputs`` are ``[top_of_stack, deeper]`` and the value is ``deeper OP top``
    -- so ``txn GroupIndex; intc_1; -`` has ``inputs=[1, GroupIndex]`` and means
    ``GroupIndex - 1``. Run ``propagate_scratch_values()`` first so a ``load N``
    of a stored ``GroupIndex-1`` forwards to the arithmetic.
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


# gtxnsa/txna array field -> (Num-field, the +1 the encoder's panic bound needs).
# ApplicationArgs/Assets are 0-based on their count (panic i >= NumX  => need
# NumX >= i+1); Accounts/Applications include an implicit element 0 = Sender /
# current app (panic i > NumX => need NumX >= i). Mirrors the encoder's
# elem_panic (chc_encoder/ops.py) so the recovered minimum unblocks exactly the
# reads the contract makes.
_ARRAY_FIELD_NUM = {
    "ApplicationArgs": ("NumAppArgs", 1),
    "Assets": ("NumAssets", 1),
    "Accounts": ("NumAccounts", 0),
    "Applications": ("NumApplications", 0),
}


def array_counts(prog: SSAProgram) -> dict[str, dict[str, int]]:
    """The minimum array-element counts a contract's ``gtxnsa``/``gtxna``/``txna``
    reads force on each group slot: ``{slot: {NumField: min_count}}``.

    A member addressed by ``F i`` must carry at least ``min_count`` ``F`` elements
    or the read panics (so the accepting path is unreachable -- exactly the
    completeTransfer vacuity: the harness pins siblings to ``NumAppArgs=0`` while
    the core call is read at ``ApplicationArgs 1``). Slots are ``relative_slot``
    strings (``"this"``, ``"this-1"``, ``"gtxn[0]"``, …). Run
    ``propagate_scratch_values()`` on ``prog`` first for relative indices.
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
        if field is not None:                     # TypeEnum==1 -> `pay`, OnCompletion==5 -> ...
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
    # Operands are TOP-FIRST: the SOURCE-order comparison is ``inputs[1] OP
    # inputs[0]``, so a non-commutative relation (``>=`` / ``<`` …) inverts if
    # read positionally (see ``reference_ssa_inputs_top_first``).
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
    return GroupShape(constraints=_constraints_from(pp.approving_exit_summary()))


def _constraints_from(preds) -> list[GroupConstraint]:
    """Distinct group constraints derivable from a predicate set (order-preserving
    dedup). The shared primitive under both the common-shape summary and the
    per-block / per-exit views."""
    out: list[GroupConstraint] = []
    seen: set[GroupConstraint] = set()
    for pred in preds:
        c = derive_constraint(pred)
        if c is not None and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def constraints_at(pp: PathPredicateAnalysis, bb) -> list[GroupConstraint]:
    """The group constraints IN FORCE at a basic block — the per-block substrate.
    Derived from ``bb_preds[bb]`` (the meet over every path reaching ``bb``), so it
    answers "what group facts are already established here" at any program point,
    not just at approving exits. This is the query layer a flow-sensitive consumer
    uses (e.g. asking whether a ``GroupSize`` bound holds at a given access site)."""
    return _constraints_from(pp.bb_preds.get(bb, frozenset()))


def per_block_constraints(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> dict:
    """``{BasicBlock: [GroupConstraint, ...]}`` for every block that has any — the
    full per-block substrate in one call (see :func:`constraints_at`)."""
    pp = pp or PathPredicateAnalysis(prog)
    out = {}
    for bb in prog.blocks.values():
        cs = constraints_at(pp, bb)
        if cs:
            out[bb] = cs
    return out


@dataclass
class ExitShape:
    """The group shape forced on the paths reaching one approving exit (or the set
    of exits that force the IDENTICAL shape). Finer than :class:`GroupShape`, which
    intersects across *all* approving exits and so shows only what's common: this
    keeps the distinct admissible shapes apart. ``exits`` is ``(line, method)``
    pairs — ``method`` is the ABI method the exit sits in when source ``method``
    info is available, else ``None``."""

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
    """All distinct per-exit group shapes a program admits (see
    :func:`analyze_per_exit`)."""

    shapes: list         # list[ExitShape]

    def render(self) -> str:
        if not self.shapes:
            return "(no approving exits)"
        return "\n".join(s.render() for s in self.shapes)

    def to_dict(self) -> dict:
        return {"exit_shapes": [s.to_dict() for s in self.shapes]}


def exit_method_lookup(prog):
    """A ``bb -> ABI method name | None`` resolver over the source ``method "sig"``
    info, cached per file. ``bb.file`` is a BASENAME, so it's resolved to a real
    path through ``prog.source_path`` (a single file, or a directory searched by
    basename). Fully defensive — no info / any failure ⇒ always ``None`` (the
    OPTIONAL ABI-label enrichment)."""
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
    """The DISTINCT group shapes a contract admits — one per approving exit,
    instead of only their intersection (:func:`analyze`).

    Each approving ``return`` contributes the group constraints in force on the
    paths that reach it; exits that force the identical shape are merged. A
    contract whose arms demand different shapes (``GroupSize==2`` on one,
    ``GroupSize==3`` on another) shows both here, where ``analyze`` shows nothing.
    When the source carries ABI ``method "sig"`` info, each exit is labelled with
    the method it belongs to — "this method forces this shape".

    (Per-exit is a meet over the paths reaching one exit, so two shapes that merge
    *before* a single return still can't be split — that needs full per-path
    enumeration. In practice distinct shapes reach distinct exits.)"""
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


# ---------------------------------------------------------------------------
# Group size + layout report (presentation over GroupShape)
# ---------------------------------------------------------------------------


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
    """A group-size + per-position *layout* view of the forced shape:
    the same :class:`GroupConstraint`s :func:`analyze` produces,
    reorganised by the group slot each one pins and rendered in the
    style of :class:`tealql.tealtools.inner_txn_report.InnerTxnReport`.

    Buckets:
      - ``Global.GroupSize`` constraints → the group size line.
      - ``Txn.GroupIndex`` constraints → this app's own position.
      - ``gtxn[N].field`` constraints → grouped under position ``N``.
        A constraint relating a position to a literal / global / this
        (either operand) is filed under that position so the slot's
        requirements read together.
      - remaining ``Txn.field`` / ``Global.field`` → "this txn" /
        "globals" sections.
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
            # Position bucket: prefer a gtxn slot on either side so the
            # slot's requirements group together.
            lhs_i = _gtxn_index(ref)
            rhs_ref = classify(rhs)
            rhs_i = _gtxn_index(rhs_ref) if rhs_ref is not None else None
            if lhs_i is not None:
                positions.setdefault(lhs_i, []).append(
                    (ref.field, c.op, _render_rhs(rhs))
                )
            elif rhs_i is not None:
                # ref is on the rhs of this slot's constraint; flip so
                # the slot field reads on the left. ``ref`` renders via
                # its own GroupRef repr (e.g. ``Global.CurrentAppAddr``).
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
                f"{c.ref.field} {c.op} {_render_rhs(c.rhs)}"
                for c in sorted(this_fields, key=_constraint_sort_key)
            ],
            "globals": [
                f"{c.ref.field} {c.op} {_render_rhs(c.rhs)}"
                for c in sorted(globals_, key=_constraint_sort_key)
            ],
        }


def analyze_layout(
    prog: SSAProgram, pp: Optional[PathPredicateAnalysis] = None
) -> GroupLayout:
    """Compute the forced group shape and present it as a size +
    per-position :class:`GroupLayout`. Companion to :func:`analyze`
    (which returns the flat constraint list)."""
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
