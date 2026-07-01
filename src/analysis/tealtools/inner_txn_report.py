"""Inner-transaction (`itxn_*`) report.

For each ``itxn_submit`` in a TEAL program, walks the chain of
``itxn_begin`` / ``itxn_next`` / ``itxn_submit`` boundaries and reports
every ``itxn_field`` op that contributes — together with the consumed
operand and (when statically known) its literal value.

    from tealtools.ssa import SSAProgram
    from tealtools.inner_txn_report import InnerTxnReport

    prog = SSAProgram("tests/dbs/xgov-db")
    prog.propagate_constants()             # optional but improves resolution
    prog.propagate_scratch_constants()     # ditto

    report = InnerTxnReport(prog)
    print(report.render())

Preconditions
-------------

Operates on the standard SSA representation — the state
:class:`tealtools.ssa.SSAProgram` is in by default, optionally after
:meth:`propagate_constants` / :meth:`propagate_scratch_constants` (those
only *add* ``const_value`` without removing anything). Per-field operand
resolution follows the consumed value's ``(file, line, idx)`` identity, so
it needs the phis and original SSAVars intact.

The boundary structure (which ``itxn_field`` belongs to which txn
within which submit-group) is computed by the inner-transaction-field
pass. The python side groups the resulting field rows into
:class:`InnerTxnGroup` objects and resolves each consumed operand by
:meth:`SSAProgram.var` / :meth:`SSAProgram.phi`.

Field values
------------

Each :class:`InnerTxnField` keeps a typed reference to the consumed
operand (``SSAVar`` / ``Phi``). :meth:`possible_values`
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

from .ssa import (
    Const,
    Phi,
    SSAProgram,
    SSAVar,
)
from .passes.frame_flow import frame_param_sources


# Inner-txn field operands: a produced value, a join, or a const literal.
Operand = Union[SSAVar, Phi, Const]


# AVM itxn fields that are *arrays*: each ``itxn_field F`` op APPENDS an
# element rather than overwriting. So N field ops for one of these names
# means an N-element array (in program order), not N alternative values
# the way repeated scalar-field writes across branches would. The report
# renders these as ordered ``[e0, e1, …]`` instead of a ``{a | b}`` set.
_ARRAY_ITXN_FIELDS = frozenset({
    "ApplicationArgs",
    "Accounts",
    "Assets",
    "Applications",
    "ApprovalProgramPages",
    "ClearStateProgramPages",
})


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
    # ``{frame_dig output -> {caller args}}`` so a param-fed value resolves to
    # the caller args instead of a symbolic frame_dig. Set by InnerTxnReport.
    frame_src: Optional[dict] = None

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
        - **Symbolic** — ``"?V#3@L42"`` or ``"?phi_…"``: the operand
          can't be described by a single producer. The ``?`` prefix
          flags "trace this in the SSA graph yourself".

        Phis expand to one entry per arg, deduplicated. A ``frame_dig`` param
        read expands the same way over its caller args (``frame_src``).
        """
        return _operand_possible_values(self.operand, frame_src=self.frame_src)

    def value_str(self) -> str:
        vals = self.possible_values()
        if len(vals) == 1:
            return vals[0]
        return "{" + " | ".join(vals) + "}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "possible_values": self.possible_values(),
        }


def _operand_possible_values(
    op: Optional[Operand], _seen: Optional[set] = None,
    frame_src: Optional[dict] = None,
) -> list[str]:
    """Shared resolver for :class:`InnerTxnField` and recursive phi /
    frame-param expansion. ``_seen`` breaks cycles (legitimate around
    recursive subroutines)."""
    if op is None:
        return ["?<unresolved>"]
    if isinstance(op, Const):
        return [op.value]
    cv = getattr(op, "const_value", None)
    if cv is not None:
        return [cv.value]
    if isinstance(op, Phi):
        return _phi_possible_values(op, _seen, frame_src)
    if isinstance(op, SSAVar):
        # A `frame_dig` param read: expand to the caller args bound to it across
        # all call sites (interprocedural, like a phi over the call-site values),
        # so a param-fed value resolves instead of showing a symbolic frame_dig.
        if frame_src and op in frame_src:
            seen = _seen or set()
            if op in seen:
                return [f"?{op!r}"]
            seen = seen | {op}
            out: list[str] = []
            seen_strs: set[str] = set()
            for arg in sorted(frame_src[op], key=repr):
                for v in _operand_possible_values(arg, seen, frame_src):
                    if v not in seen_strs:
                        seen_strs.add(v)
                        out.append(v)
            if out:
                return out
        # SSAVar with a defining assignment → describe by the producing op.
        a = getattr(op, "defined_by", None)
        if a is not None:
            return [_describe_assignment(a)]
    # SSAVar whose ``defined_by`` was cleared (e.g. by
    # ``eliminate_dead_constants`` after the constant was inlined into
    # all consumers). Fall back to the operand identifier.
    return [f"?{op!r}"]


def _describe_assignment(a) -> str:
    """One-liner description of an :class:`tealtools.ssa.Assignment`'s RHS,
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


def _phi_possible_values(
    phi: Phi, _seen: Optional[set] = None, frame_src: Optional[dict] = None,
) -> list[str]:
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
        for v in _operand_possible_values(arg, _seen, frame_src):
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

    def to_dict(self) -> dict:
        return {
            "begin": {"line": self.begin_line, "kind": self.begin_kind},
            "end": {"line": self.end_line, "kind": self.end_kind},
            "fields": [f.to_dict() for f in self.fields],
        }


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

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "submit_line": self.submit_line,
            "txns": [t.to_dict() for t in self.txns],
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class InnerTxnReport:
    """Aggregates inner-transaction-field rows into per-submit groups.

    Construction is cheap — it only walks the cached graph annotation,
    no re-evaluation. Re-running ``SSAProgram`` propagation passes
    after construction is fine: the operands stored on
    :class:`InnerTxnField` carry references to the SSA layer's typed
    objects, so any subsequently-set ``const_value`` is reflected on
    the next :meth:`possible_values` call.
    """

    def __init__(self, prog: SSAProgram):
        self.prog = prog
        self.groups: list[InnerTxnGroup] = self._build()

    # -- construction -----------------------------------------------

    def _build(self) -> list[InnerTxnGroup]:
        rows = self.prog._graph.graph.get("inner_txn_fields") or []
        # Interprocedural frame edges so a param-fed field value (e.g. a
        # forwarded ApplicationID) resolves to its caller args, not a symbolic
        # frame_dig. Best-effort — empty for a program with no proto subs.
        try:
            frame_src = frame_param_sources(self.prog)
        except Exception:
            frame_src = {}

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
                frame_src=frame_src,
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
        # (file, begin_line) -> ALL txns starting there. The same boundary line
        # is both end-of-txn_k and start-of-txn_{k+1}; on DIVERGENT control paths
        # one boundary opcode can start more than one successor txn (e.g. an
        # itxn_next followed by either another itxn_next or an itxn_submit
        # depending on the branch). A single-value index would silently keep only
        # the last, mis-building one chain and dropping the other.
        by_start: dict[tuple[str, int], list[InnerTxn]] = {}
        for k, v in per_pair.items():
            by_start.setdefault((k[0], v.begin_line), []).append(v)

        groups: list[InnerTxnGroup] = []

        def _walk(file: str, chain: list) -> None:
            cur = chain[-1]
            succs = ([t for t in by_start.get((file, cur.end_line), [])
                      if t is not cur]
                     if cur.end_kind == "itxn_next" else [])
            if not succs:                  # closed at a submit (or dead-ends)
                groups.append(InnerTxnGroup(
                    file=file, submit_line=cur.end_line, txns=list(chain)))
                return
            for s in succs:                # fork: one continuation per successor
                _walk(file, chain + [s])

        for (file, start_line, end_line), txn in sorted(
            per_pair.items(), key=lambda kv: (kv[0][0], kv[0][1])
        ):
            if txn.begin_kind != "itxn_begin":
                continue  # follows from a chain head only.
            _walk(file, [txn])

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
        """Map a field row's ``(def_kind, def_file, def_line, def_idx)``
        back to the corresponding SSAProgram object.

        Phis referenced by the field rows may not have been
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
                    lines = ", ".join(f"L{f.line}" for f in fs)
                    if name in _ARRAY_ITXN_FIELDS:
                        # Array-valued field: each itxn_field op appends an
                        # element, so render the ops in program order
                        # (fs is line-sorted) as an ordered sequence.
                        elems = ", ".join(f.value_str() for f in fs)
                        out.append(f"    {name.ljust(w)} = [{elems}]  (set@{lines})")
                    elif len(fs) == 1:
                        out.append(f"    {name.ljust(w)} = {fs[0].value_str()}  (set@L{fs[0].line})")
                    else:
                        # Scalar field written by multiple itxn_field ops
                        # along different paths — show the union of values.
                        union_vals: list[str] = []
                        for f in fs:
                            for v in f.possible_values():
                                if v not in union_vals:
                                    union_vals.append(v)
                        rendered = "{" + " | ".join(union_vals) + "}"
                        out.append(f"    {name.ljust(w)} = {rendered}  (set@{lines})")
            out.append("")
        return "\n".join(out)

    def print(self) -> None:
        print(self.render())

    def to_dict(self) -> dict:
        return {"groups": [g.to_dict() for g in self.groups]}
