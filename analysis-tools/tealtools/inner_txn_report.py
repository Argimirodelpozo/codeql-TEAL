"""Inner-transaction (`itxn_*`) report.

For each ``itxn_submit`` in a TEAL program, walks the chain of
``itxn_begin`` / ``itxn_next`` / ``itxn_submit`` boundaries and reports
every ``itxn_field`` op that contributes — together with the consumed
operand and (when statically known) its literal value.

    from teal_ssa import SSAProgram
    from teal_inner_txn_report import InnerTxnReport

    prog = SSAProgram("tests/dbs/xgov-db")
    prog.propagate_constants()             # optional but improves resolution
    prog.propagate_scratch_constants()     # ditto

    report = InnerTxnReport(prog)
    print(report.render())

Preconditions
-------------

Operates on the **pre-materialized, pre-dead-elimination** SSA
representation — the state :class:`teal_ssa.SSAProgram` is in by
default, optionally after :meth:`propagate_constants` /
:meth:`propagate_scratch_constants` (those only *add* ``const_value``
without removing anything).

- :meth:`SSAProgram.materialize_phis` destroys the phi structure
  (replaces phis with :class:`MatPhiVar` copy assignments), at which
  point joins are no longer visible as a single phi-args expansion.
- :meth:`SSAProgram.eliminate_dead_constants` drops every SSAVar
  whose ``const_value`` was inlined at every consumer. This breaks
  per-field operand resolution: the QL query reports the consumed
  value's ``(file, line, idx)`` identity, and after elimination
  ``prog.var(...)`` returns ``None`` for those — so a literal-pusher
  field (``pushint 100 / itxn_field Amount``) renders as
  ``?<unresolved>`` instead of ``100``.

The constructor checks both flags and raises if either is set. Build
a fresh :class:`SSAProgram` if you've already run those passes for
some other downstream use.

The boundary structure (which ``itxn_field`` belongs to which txn
within which submit-group) is computed in QL by
``InnerTransactionField.contributesToItxn`` — exposed to Python via
``innerTxnFields.ql``. The python side groups the QL rows into
:class:`InnerTxnGroup` objects and resolves each consumed operand by
:meth:`SSAProgram.var` / :meth:`SSAProgram.phi`.

Field values
------------

Each :class:`InnerTxnField` keeps a typed reference to the consumed
operand (``SSAVar`` / ``Phi`` / ``MatPhiVar``). :meth:`possible_values`
flattens this into a list of literal-or-symbolic strings:

- An :class:`SSAVar` / :class:`Phi` whose ``const_value`` is set →
  one literal entry.
- A :class:`Phi` with a populated ``args`` list, all resolving to
  literals → one entry per arg's literal value (deduplicated).
- A symbolic operand (no ``const_value``, mixed phi args) → one
  entry containing the operand's identifier (e.g. ``V#3@L42``)
  prefixed with ``?`` to mark "not statically known".

Runs cleanly without any propagation pass, but values are easier to
read once :meth:`SSAProgram.propagate_constants` and (where relevant)
:meth:`propagate_scratch_constants` have been run on the program.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Iterable, Optional, Union

from teal_ssa import (
    Const,
    Phi,
    SSAProgram,
    SSAVar,
)


# Pre-materialized SSA only: ``MatPhiVar`` cannot appear here.
Operand = Union[SSAVar, Phi, Const]


@dataclass
class InnerTxnField:
    """A single ``itxn_field F`` op in the program.

    ``operand`` is the typed SSA operand consumed by the field op.
    Resolve to literal(s) via :meth:`possible_values`.
    """

    name: str
    file: str
    line: int
    operand: Optional[Operand]

    def possible_values(self) -> list[str]:
        """Flatten ``operand`` to a list of value descriptions.

        Each entry is one of three shapes, in order of preference:

        - **Literal** — ``"100"``, ``"0x1234"``, ``"\"hello\""``: the
          operand is a :class:`Const` or has ``const_value`` set.
        - **Source op** — ``"txn Sender"``, ``"txna ApplicationArgs 0"``,
          ``"+ (V#3@L20, 100)"``: the operand is an :class:`SSAVar`
          whose runtime value is determined by the producing
          opcode. Often *this* is the most useful answer — for
          ``txn Sender`` and friends the value isn't a static literal
          but it has a meaningful semantic name.
        - **Symbolic** — ``"?V#3@L42"`` or ``"?phi_…"``: the operand is
          a :class:`MatPhiVar` or otherwise can't be described by a
          single producer. The ``?`` prefix flags "trace this in the
          SSA graph yourself".

        Phis expand to one entry per arg, deduplicated.
        """
        return _operand_possible_values(self.operand)

    def value_str(self) -> str:
        vals = self.possible_values()
        if len(vals) == 1:
            return vals[0]
        return "{" + " | ".join(vals) + "}"


def _operand_possible_values(
    op: Optional[Operand], _seen: Optional[set] = None
) -> list[str]:
    """Shared resolver for :class:`InnerTxnField` and recursive phi
    expansion. ``_seen`` breaks phi cycles (legitimate around
    recursive subroutines)."""
    if op is None:
        return ["?<unresolved>"]
    if isinstance(op, Const):
        return [op.value]
    cv = getattr(op, "const_value", None)
    if cv is not None:
        return [cv.value]
    if isinstance(op, Phi):
        return _phi_possible_values(op, _seen)
    # SSAVar with a defining assignment → describe by the producing op.
    if isinstance(op, SSAVar):
        a = getattr(op, "defined_by", None)
        if a is not None:
            return [_describe_assignment(a)]
    # SSAVar whose ``defined_by`` was cleared (e.g. by
    # ``eliminate_dead_constants`` after the constant was inlined into
    # all consumers). Fall back to the operand identifier.
    return [f"?{op!r}"]


def _describe_assignment(a) -> str:
    """One-liner description of an :class:`teal_ssa.Assignment`'s RHS,
    suitable for in-line use in a value summary.

    Reads the ``Assignment`` rather than reformatting from scratch so
    immediates like ``txn Sender`` / ``txna ApplicationArgs 0`` /
    ``pushint 5`` come through unchanged. Includes input operand
    identifiers in parens for ops that consume from the stack
    (``+``, ``concat``, ``btoi``, ...) so the consumer can chain into
    the dataflow if they want.
    """
    head = a.op
    if a.immediates:
        head = f"{head} {a.immediates}"
    if a.inputs:
        in_str = ", ".join(repr(i) for i in a.inputs)
        return f"{head}({in_str})"
    return head


def _phi_possible_values(phi: Phi, _seen: Optional[set] = None) -> list[str]:
    """Expand a phi's args to their value descriptions.

    Deduplicated so two paths that push the same value don't show up
    twice. Uses a ``_seen`` set to break phi-of-phi cycles."""
    if _seen is None:
        _seen = set()
    if phi in _seen:
        return [f"?{phi!r}"]
    _seen.add(phi)
    if not phi.args:
        return [f"?{phi!r}"]
    out: list[str] = []
    seen_strs: set[str] = set()
    for arg in phi.args:
        for v in _operand_possible_values(arg, _seen):
            if v not in seen_strs:
                seen_strs.add(v)
                out.append(v)
    return out


@dataclass
class InnerTxn:
    """One inner transaction within a submit-group.

    Delimited by an ``itxn_begin``/``itxn_next`` (``begin_line``) and
    the next ``itxn_next``/``itxn_submit`` (``end_line``).

    ``fields`` is an ordered list of every ``itxn_field`` event that
    contributed — duplicate field names are kept (e.g. ``Amount`` set
    in two separate branches that both flow into this txn's submit).
    Use :meth:`fields_by_name` to collapse by name.
    """

    begin_line: int
    begin_kind: str  # "itxn_begin" or "itxn_next"
    end_line: int
    end_kind: str    # "itxn_next" or "itxn_submit"
    fields: list[InnerTxnField] = dc_field(default_factory=list)

    def fields_by_name(self) -> dict[str, list[InnerTxnField]]:
        out: dict[str, list[InnerTxnField]] = {}
        for f in self.fields:
            out.setdefault(f.name, []).append(f)
        return out


@dataclass
class InnerTxnGroup:
    """An ``itxn_begin`` … ``itxn_submit`` group of one-or-more txns.

    A group is one atomic submit. ``txns`` lists each txn in the group
    in source order; a single ``itxn_begin`` followed by N
    ``itxn_next``s plus one ``itxn_submit`` produces ``N+1`` txns.
    """

    file: str
    submit_line: int
    txns: list[InnerTxn]

    def __repr__(self) -> str:
        return (
            f"InnerTxnGroup({self.file}:submit@L{self.submit_line}, "
            f"{len(self.txns)} txn{'s' if len(self.txns) != 1 else ''})"
        )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class InnerTxnReport:
    """Aggregates ``innerTxnFields.ql`` rows into per-submit groups.

    Construction is cheap — it only walks the cached graph annotation,
    no QL re-evaluation. Re-running ``SSAProgram`` propagation passes
    after construction is fine: the operands stored on
    :class:`InnerTxnField` carry references to the SSA layer's typed
    objects, so any subsequently-set ``const_value`` is reflected on
    the next :meth:`possible_values` call.
    """

    def __init__(self, prog: SSAProgram):
        if getattr(prog, "_materialized", False):
            raise ValueError(
                "InnerTxnReport requires the pre-materialized SSA representation; "
                "this SSAProgram has had `materialize_phis()` called on it, which "
                "replaces Phi nodes with MatPhiVar copy assignments. Build a fresh "
                "SSAProgram or run this analysis before materialization."
            )
        if getattr(prog, "_dead_eliminated", False):
            raise ValueError(
                "InnerTxnReport requires the pre-dead-elimination SSA representation; "
                "`eliminate_dead_constants()` drops SSAVars whose const_value was "
                "inlined into every consumer, which breaks per-field operand "
                "resolution (the consumed SSAVar referenced by the CodeQL row is no "
                "longer in prog.vars). Build a fresh SSAProgram or run this analysis "
                "before dead elimination."
            )
        self.prog = prog
        self.groups: list[InnerTxnGroup] = self._build()

    # -- construction -----------------------------------------------

    def _build(self) -> list[InnerTxnGroup]:
        rows = self.prog._graph.graph.get("inner_txn_fields") or []

        # Bucket every (start, end) pair to its (start_line, end_line,
        # start_kind, end_kind) key. The (file, start, end) triple is
        # unique per physical pair of itxn-boundary opcodes — the same
        # pair can appear in many rows (one per contributing field).
        # We use ``(file, start_line, end_line)`` as the bucket key so
        # we can later chain consecutive (start, end) pairs that share
        # an ``itxn_next`` boundary into a single submit group.
        Boundary = tuple[str, int, int]  # (file, start_line, end_line)
        per_pair: dict[Boundary, InnerTxn] = {}
        # Resolve the operand for each field row through the SSA layer.
        for r in rows:
            file = r["field_file"]
            key: Boundary = (file, r["start_line"], r["end_line"])
            txn = per_pair.get(key)
            if txn is None:
                txn = InnerTxn(
                    begin_line=r["start_line"],
                    begin_kind=r["start_kind"],
                    end_line=r["end_line"],
                    end_kind=r["end_kind"],
                )
                per_pair[key] = txn
            txn.fields.append(InnerTxnField(
                name=r["field_name"],
                file=file,
                line=r["field_line"],
                operand=self._resolve_operand(r),
            ))

        # Order each txn's fields by source line for stable rendering.
        for txn in per_pair.values():
            txn.fields.sort(key=lambda f: f.line)

        # Walk submit-back: each `itxn_submit` is a group end. Build
        # backwards through `itxn_next` chains until we hit an
        # `itxn_begin`. The result is one InnerTxnGroup per submit,
        # txns ordered front-to-back.
        # Index pairs by their end-line to find the txn that closes
        # at a given itxn_next/submit, and by their start-line to walk
        # forward.
        by_start: dict[tuple[str, int], InnerTxn] = {
            (k[0], v.begin_line): v for k, v in per_pair.items()
        }
        # Some txns close at itxn_next and a *different* txn starts at
        # the same line — the same line can be both end of txn_k and
        # start of txn_{k+1}. Use the (file, start_line) lookup to
        # follow chains forward.
        groups: list[InnerTxnGroup] = []
        for (file, start_line, end_line), txn in sorted(
            per_pair.items(), key=lambda kv: (kv[0][0], kv[0][1])
        ):
            if txn.begin_kind != "itxn_begin":
                continue  # follows from a chain head only.
            chain = [txn]
            while chain[-1].end_kind == "itxn_next":
                next_txn = by_start.get((file, chain[-1].end_line))
                if next_txn is None or next_txn is chain[-1]:
                    break
                chain.append(next_txn)
            submit_line = chain[-1].end_line
            groups.append(InnerTxnGroup(
                file=file, submit_line=submit_line, txns=chain,
            ))

        # Also surface single-pair "lonely" groups even when their
        # begin isn't an itxn_begin — defensively (well-formed TEAL
        # always has a begin, but malformed input shouldn't crash us).
        seen_txns = {id(t) for g in groups for t in g.txns}
        for txn in per_pair.values():
            if id(txn) in seen_txns:
                continue
            groups.append(InnerTxnGroup(
                file=next(k[0] for k, v in per_pair.items() if v is txn),
                submit_line=txn.end_line,
                txns=[txn],
            ))

        groups.sort(key=lambda g: (g.file, g.submit_line))
        return groups

    def _resolve_operand(self, row: dict) -> Optional[Operand]:
        """Map a CodeQL row's ``(def_kind, def_file, def_line, def_idx)``
        back to the corresponding SSAProgram object.

        Phis emitted by ``innerTxnFields.ql`` may not have been
        materialised by ``SSAProgram.__init__`` (lazy materialisation
        only creates phis referenced in some ``Assignment.inputs``).
        Every itxn_field IS such an assignment, so the consumed phi
        WILL be materialised — but we still guard for ``None`` and
        return it through to ``possible_values``, which renders
        ``?<unresolved>``.
        """
        kind = row["def_kind"]
        if kind == "SSAVar":
            return self.prog.var(row["def_file"], row["def_line"], row["def_idx"])
        if kind in ("DirectPhi", "IndirectPhi"):
            return self.prog.phi(row["def_file"], row["def_line"], kind, row["def_idx"])
        return None

    # -- public -----------------------------------------------------

    def __iter__(self) -> Iterable[InnerTxnGroup]:
        return iter(self.groups)

    def __len__(self) -> int:
        return len(self.groups)

    def render(self) -> str:
        if not self.groups:
            return "(no inner transactions)"
        out: list[str] = []
        for g in self.groups:
            out.append(f"=== Inner-txn group  {g.file}  submit@L{g.submit_line}  ({len(g.txns)} txn) ===")
            for i, txn in enumerate(g.txns, 1):
                header = f"  Txn {i}  ({txn.begin_kind}@L{txn.begin_line} → {txn.end_kind}@L{txn.end_line})"
                out.append(header)
                if not txn.fields:
                    out.append("    (no fields)")
                    continue
                # Group fields by name for compact rendering, but keep
                # the order of first occurrence so the listing tracks
                # source layout.
                seen_names: list[str] = []
                grouped = txn.fields_by_name()
                for f in txn.fields:
                    if f.name not in seen_names:
                        seen_names.append(f.name)
                w = max(len(n) for n in seen_names)
                for name in seen_names:
                    fs = grouped[name]
                    if len(fs) == 1:
                        out.append(f"    {name.ljust(w)} = {fs[0].value_str()}  (set@L{fs[0].line})")
                    else:
                        # Multiple itxn_field F ops along different
                        # paths — show each with its set-line.
                        union_vals: list[str] = []
                        for f in fs:
                            for v in f.possible_values():
                                if v not in union_vals:
                                    union_vals.append(v)
                        rendered = "{" + " | ".join(union_vals) + "}"
                        lines = ", ".join(f"L{f.line}" for f in fs)
                        out.append(f"    {name.ljust(w)} = {rendered}  (set@{lines})")
            out.append("")
        return "\n".join(out)

    def print(self) -> None:
        print(self.render())
