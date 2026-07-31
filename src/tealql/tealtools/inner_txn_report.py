"""Inner-transaction (``itxn_*``) report: for each ``itxn_submit``, walk the
``itxn_begin`` / ``itxn_next`` / ``itxn_submit`` boundary chain and report every
contributing ``itxn_field`` op with its consumed operand and, where statically
known, that operand's literal value.

Runs on default SSA; ``propagate_constants`` / ``propagate_scratch_constants``
only ADD ``const_value``, so they sharpen values without changing structure.
Operand resolution keys on the consumed value's ``(file, line, idx)`` identity —
it needs the phis and original SSAVars INTACT, so a pass that rewrites or
eliminates them leaves fields unresolved.
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
from .passes.frame_flow import frame_value_sources


# Inner-txn field operands: a produced value, a join, or a const literal.
Operand = Union[SSAVar, Phi, Const]


# AVM itxn fields that are ARRAYS: ``itxn_field F`` APPENDS an element rather
# than overwriting, so N ops on one of these names mean an N-element array in
# program order — NOT N alternative values, the way repeated scalar writes
# across branches do. Rendered ``[e0, e1, …]``, not ``{a | b}``.
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
    """A single ``itxn_field F`` op and the typed SSA ``operand`` it consumes
    (resolve to literals via :meth:`possible_values`)."""

    name: str
    file: str
    line: int
    operand: Optional[Operand]
    # ``{frame_dig output -> {caller args}}``, set by InnerTxnReport, so a
    # param-fed value resolves to caller args, not a symbolic frame_dig.
    frame_src: Optional[dict] = None

    def possible_values(self) -> list[str]:
        """Flatten ``operand`` to value descriptions, in order of preference:
        the literal (``100``), else the producing op (``txn Sender``,
        ``+ (V#3@L20, 100)``), else the ``?``-prefixed operand identifier
        meaning "not statically known, trace it yourself".

        Phis expand to one entry per arg, deduplicated; a ``frame_dig`` param
        read expands the same way over its caller args (``frame_src``)."""
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
    """Shared operand resolver; ``_seen`` breaks cycles, which are legitimate
    around recursive subroutines."""
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
        # A `frame_dig` param read: expand over the caller args bound at every
        # call site — interprocedural, like a phi over the call-site values.
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
    # ``defined_by`` cleared (const inlined into every consumer) — fall back to
    # the operand identifier.
    return [f"?{op!r}"]


def _describe_assignment(a) -> str:
    """One-line description of an ``Assignment``'s RHS: op plus immediates
    verbatim (``txn Sender``, ``pushint 5``), with input operand identifiers in
    parens for stack-consuming ops so a reader can chain into the dataflow."""
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
    """Expand a phi's args to value descriptions, deduplicated so two paths
    pushing the same value show once; ``_seen`` breaks phi-of-phi cycles."""
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
    """One inner transaction, delimited by ``itxn_begin``/``itxn_next`` and the
    next ``itxn_next``/``itxn_submit``.

    ``fields`` keeps duplicate names — ``Amount`` set in two branches that both
    reach this submit stays two entries; :meth:`fields_by_name` collapses."""

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
    """One atomic ``itxn_begin`` … ``itxn_submit`` submit, ``txns`` in source
    order — one begin plus N ``itxn_next`` gives ``N+1`` txns."""

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
    """Aggregates inner-transaction-field rows into per-submit groups; operands
    stay live references into the SSA layer, so a ``const_value`` set by a later
    propagation pass shows up on the next :meth:`possible_values` call."""

    def __init__(self, prog: SSAProgram):
        self.prog = prog
        self.groups: list[InnerTxnGroup] = self._build()

    # -- construction -----------------------------------------------

    def _build(self) -> list[InnerTxnGroup]:
        self.prog._ensure_inner_txn_fields()
        rows = self.prog._graph.graph.get("inner_txn_fields") or []
        # Interprocedural frame edges so a param-fed field value resolves to its
        # caller args. Best-effort — empty for a program with no proto subs.
        try:
            frame_src = frame_value_sources(self.prog)
        except Exception:
            frame_src = {}

        # Bucket rows by (file, start_line, end_line): unique per physical pair
        # of boundary opcodes (one pair spans many rows, one per contributing
        # field), and the key that later chains pairs sharing an ``itxn_next``
        # boundary into one submit group.
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

        # (file, begin_line) -> ALL txns starting there; each chain is then
        # walked forward to its submit, one group per submit. A boundary line is
        # both end-of-txn_k and start-of-txn_{k+1}, and on DIVERGENT paths one
        # boundary can start MORE THAN ONE successor txn — a single-value index
        # would silently keep the last and drop the other chain.
        by_start: dict[tuple[str, int], list[InnerTxn]] = {}
        for k, v in per_pair.items():
            by_start.setdefault((k[0], v.begin_line), []).append(v)

        groups: list[InnerTxnGroup] = []

        def _walk(file: str, chain: list) -> None:
            cur = chain[-1]
            # Exclude every txn already ON this chain, not just ``cur``: the
            # boundary pass is path-insensitive, so a loop body with two
            # `itxn_next` ops yields mutually-reaching pairs (a→b and b→a) and
            # the recursion never terminates.
            on_chain = {id(t) for t in chain}
            succs = ([t for t in by_start.get((file, cur.end_line), [])
                      if id(t) not in on_chain]
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

        # Lonely pairs whose begin isn't an itxn_begin: well-formed TEAL always
        # has one, but malformed input must still be reported, not dropped.
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
        """Map a field row's ``(def_kind, def_file, def_line, def_idx)`` back to
        its SSAProgram object, or ``None`` — which ``possible_values`` renders
        as ``?<unresolved>``."""
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
                # Group by name, in order of first occurrence so the listing
                # still tracks source layout.
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
                        # Appends, not overwrites — render the line-sorted ops
                        # as an ordered sequence.
                        elems = ", ".join(f.value_str() for f in fs)
                        out.append(f"    {name.ljust(w)} = [{elems}]  (set@{lines})")
                    elif len(fs) == 1:
                        out.append(f"    {name.ljust(w)} = {fs[0].value_str()}  (set@L{fs[0].line})")
                    else:
                        # One scalar field written on several paths — union.
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
