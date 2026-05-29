"""Python view of the QL-computed coarse taint-flow graph.

Loads rows from ``taintFlowEdges.ql`` (cached in the per-DB
``~/.cache/teal-graphs/`` directory) into a :class:`networkx.DiGraph`
and exposes refinement-friendly queries on top.

The QL side is intentionally *lenient* — it unions
:func:`LocalFlow::localFlowStep` (narrow) +
:func:`LocalFlow::localSsaFlowStep` (full SSA def-use, phi) +
:func:`SubroutineFlow::simpleLocalFlowStep` (cross-subroutine) +
a generic "every consumed input → every produced output" step +
explicit phi-arg edges, so the graph captures arithmetic / bytemath /
hash / slice / cross-BB phi chains the narrower predicates miss.

Multiple QL channels can fire for the same ``(src, dst)`` pair —
those collapse into a single edge whose ``kinds`` set names every
contributing channel:

- ``callsub`` — caller→callee args, callee→caller returns.
- ``scratch`` — ``store N`` → ``load N`` (across BBs).
- ``identity`` — value-identity step (SSA def-use / shuffle / phi).
- ``subroutine`` — extra step from :mod:`SubroutineFlow`.
- ``broad`` — ``LocalFlow::localFlowStep`` (narrow).
- ``generic`` — the lenient consumes-produces step.

Refinement passes (see :mod:`tealtools.dataflow.refiners`) chain via
:meth:`TaintGraph.prune` / :meth:`TaintGraph.annotate` to fold in
Python-side knowledge: const folding via ``mustValues``, range
narrowing via ``extract`` immediates, predicate-based suppression,
etc.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

import networkx as nx

from ..ssa import SSAProgram


@dataclass(frozen=True)
class Node:
    """A node in the coarse taint graph.

    ``(file, line, ql_class)`` uniquely identifies a Dataflow::Node
    for our purposes. ``ql_class`` is the AST class name from
    ``getAPrimaryQlClass()`` (e.g. ``"TxnaOpcode"``,
    ``"BoxPutOpcode"``, ``"PhiNode"``).
    """

    file: str
    line: int
    ql_class: str

    def __repr__(self) -> str:
        return f"{self.ql_class}@{self.file}:L{self.line}"


@dataclass
class TaintGraph:
    """Graph wrapper with refinement API.

    One edge per ``(src, dst)`` pair; the QL flow channels
    (``callsub`` / ``scratch`` / ``identity`` / ``subroutine`` /
    ``broad`` / ``generic``) collapse into a ``kinds`` set on the
    edge data so refinements can filter (``"callsub" in
    edge["kinds"]``) without dealing with parallel edges.
    """

    g: nx.DiGraph
    prog: SSAProgram

    @classmethod
    def of(cls, prog: SSAProgram) -> "TaintGraph":
        """Build the graph from ``prog``'s cached QL rows. Annotates
        each node with the underlying TEAL opcode (looked up from
        ``prog.assignments`` by ``(file, line)``) — useful for
        ``find(op="box_create")``-style queries since the QL class
        name from ``getAPrimaryQlClass()`` is sometimes a parent
        class (e.g. ``ZeroArgumentOpcode`` for ``box_create``).

        Multiple QL channels firing for the same ``(src, dst)`` pair
        collapse into a single edge whose ``kinds`` set lists every
        channel that contributed.
        """
        # Run const propagation so node-level value annotations include
        # phi unification + arithmetic folds. Idempotent.
        prog.propagate_constants()

        # (file, line) → (op, immediates, const_values) — the const_values
        # tuple is sorted to keep node attrs deterministic; each entry
        # is ``(kind, value)`` where ``kind`` ∈ ``{"int", "bytes"}``.
        meta_by_loc: dict[
            tuple[str, int],
            tuple[str, str, tuple[tuple[str, str], ...]],
        ] = {}
        for a in prog.assignments:
            cvs: list[tuple[str, str]] = []
            for out in a.outputs:
                cv = getattr(out, "const_value", None)
                if cv is not None:
                    cvs.append((cv.kind, cv.value))
            meta_by_loc[(a.location.file, a.location.line)] = (
                a.op, a.immediates.strip(), tuple(cvs),
            )
        rows = _flow_rows_for(prog)
        g: nx.DiGraph = nx.DiGraph()

        def _add(node: "Node") -> None:
            meta = meta_by_loc.get((node.file, node.line))
            if meta is not None:
                op, im, cvs = meta
                g.add_node(node, op=op, immediates=im, const_values=cvs)
            else:
                g.add_node(node, op=None, immediates=None, const_values=())

        for row in rows:
            (sf, sl, sc, df, dl, dc, kind) = row
            src = Node(file=sf, line=int(sl), ql_class=sc)
            dst = Node(file=df, line=int(dl), ql_class=dc)
            _add(src)
            _add(dst)
            if g.has_edge(src, dst):
                g[src][dst]["kinds"].add(kind)
            else:
                g.add_edge(src, dst, kinds={kind})
        return cls(g=g, prog=prog)

    def op_of(self, node: Node) -> Optional[str]:
        """The TEAL opcode at this node (e.g. ``"box_create"``,
        ``"asset_params_get"``). ``None`` for nodes that don't
        correspond to an SSA assignment in ``prog.assignments``
        (rare — synthetic / phi nodes)."""
        if node not in self.g:
            return None
        return self.g.nodes[node].get("op")

    def immediates_of(self, node: Node) -> Optional[str]:
        """The TEAL immediates string at this node (e.g.
        ``"ApplicationArgs 1"`` for ``txna ApplicationArgs 1``).
        ``None`` if no SSA assignment matches."""
        if node not in self.g:
            return None
        return self.g.nodes[node].get("immediates")

    def const_values_at(self, node: Node) -> tuple[tuple[str, str], ...]:
        """Concrete literals known to be produced by this node, after
        :meth:`SSAProgram.propagate_constants`. Each entry is
        ``(kind, value)`` where ``kind`` ∈ ``{"int", "bytes"}``.

        Empty tuple means *no output of this op resolves to a literal*
        — either it's a runtime value (txn fields, asset_params_get,
        non-folding arithmetic) or it's a multi-output op where none
        survived const propagation.
        """
        if node not in self.g:
            return ()
        return self.g.nodes[node].get("const_values") or ()

    def is_const_at(self, node: Node) -> bool:
        """True iff *every* output of this op has a known literal —
        i.e. nothing flowing out of this node is attacker-controlled.
        Useful as a pruning predicate: an edge whose source ``is_const``
        is *known data*, not taint."""
        cvs = self.const_values_at(node)
        if not cvs:
            return False
        # Match against the assignment's actual output count via prog.
        a = self._assignment_at(node)
        if a is None:
            return False
        return len(cvs) == len(a.outputs)

    # --- queries ------------------------------------------------------

    def nodes(self) -> Iterable[Node]:
        return self.g.nodes  # type: ignore[return-value]

    def edges(self) -> Iterator[tuple[Node, Node, dict]]:
        for u, v, data in self.g.edges(data=True):
            yield u, v, data

    def edges_by_kind(self) -> dict[str, int]:
        """Count how many edges carry each kind. An edge with multiple
        kinds counts once per kind, so the sum can exceed the edge
        count."""
        out: dict[str, int] = defaultdict(int)
        for _, _, data in self.g.edges(data=True):
            for k in data.get("kinds", ()):
                out[k] += 1
        return dict(out)

    def edges_with_kind(self, kind: str) -> Iterator[tuple[Node, Node, dict]]:
        """Iterate edges where ``kind`` is one of the contributing
        channels. Convenient for refinements that want to apply
        per-channel rules."""
        for u, v, data in self.g.edges(data=True):
            if kind in data.get("kinds", ()):
                yield u, v, data

    def predecessors(self, node: Node) -> list[Node]:
        return list(self.g.predecessors(node))

    def successors(self, node: Node) -> list[Node]:
        return list(self.g.successors(node))

    def reachable_from(self, src: Node) -> set[Node]:
        if src not in self.g:
            return set()
        return set(nx.descendants(self.g, src)) | {src}

    def reachable_to(self, dst: Node) -> set[Node]:
        if dst not in self.g:
            return set()
        return set(nx.ancestors(self.g, dst)) | {dst}

    def reaches(self, src: Node, dst: Node) -> bool:
        return src is dst or (src in self.g and dst in self.reachable_from(src))

    def paths(
        self,
        src: Node,
        dst: Node,
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[Node]]:
        """Simple paths from ``src`` to ``dst``, sorted shortest-first.
        Capped to keep enumeration bounded on programs with many
        branches."""
        if src not in self.g or dst not in self.g:
            return []
        out: list[list[Node]] = []
        cutoff = max_length if max_length is not None else None
        for path in nx.all_simple_paths(self.g, src, dst, cutoff=cutoff):
            out.append(list(path))
            if len(out) >= max_paths:
                break
        out.sort(key=len)
        return out

    def find(
        self,
        *,
        op: Optional[str] = None,
        immediates: Optional[str] = None,
        ql_class: Optional[str] = None,
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> list[Node]:
        """Node lookup by any combination of:

        - ``op`` — TEAL opcode (e.g. ``"txna"``, ``"box_create"``).
        - ``immediates`` — the immediates string (e.g.
          ``"ApplicationArgs 1"``, ``"AssetName"``). Lets you pin a
          specific source like *every* read of ``ApplicationArgs 1``.
        - ``ql_class`` — QL class name (e.g. ``"TxnaOpcode"``).
        - ``file``, ``line``.

        All-None returns every node.
        """
        out: list[Node] = []
        for n in self.g.nodes:
            attrs = self.g.nodes[n]
            if ql_class is not None and n.ql_class != ql_class:
                continue
            if file is not None and n.file != file:
                continue
            if line is not None and n.line != line:
                continue
            if op is not None and attrs.get("op") != op:
                continue
            if immediates is not None and attrs.get("immediates") != immediates:
                continue
            out.append(n)
        return out

    # --- multi-source / multi-sink queries ----------------------------

    def reachable_from_any(self, srcs: Iterable[Node]) -> set[Node]:
        """Union of :meth:`reachable_from` over a node set."""
        out: set[Node] = set()
        for s in srcs:
            if s in self.g:
                out |= self.reachable_from(s)
        return out

    def reachable_to_any(self, dsts: Iterable[Node]) -> set[Node]:
        """Union of :meth:`reachable_to` over a node set."""
        out: set[Node] = set()
        for d in dsts:
            if d in self.g:
                out |= self.reachable_to(d)
        return out

    def paths_between(
        self,
        srcs: Iterable[Node],
        dsts: Iterable[Node],
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[Node]]:
        """Simple paths from any node in ``srcs`` to any node in
        ``dsts``, sorted shortest-first, capped at ``max_paths`` total
        across all (src, dst) pairs."""
        out: list[list[Node]] = []
        srcs_list = [s for s in srcs if s in self.g]
        dsts_set = {d for d in dsts if d in self.g}
        for s in srcs_list:
            for d in dsts_set:
                for path in self.paths(s, d, max_paths=max_paths, max_length=max_length):
                    out.append(path)
                    if len(out) >= max_paths:
                        out.sort(key=len)
                        return out
        out.sort(key=len)
        return out

    # --- refinement ---------------------------------------------------

    def prune(self, predicate: Callable[[Node, Node, dict], bool]) -> "TaintGraph":
        """Drop every edge for which ``predicate(u, v, data)`` returns
        ``True``. Mutates ``self.g`` and returns ``self`` for chaining."""
        to_drop: list[tuple[Node, Node]] = [
            (u, v) for u, v, data in self.g.edges(data=True)
            if predicate(u, v, data)
        ]
        for u, v in to_drop:
            self.g.remove_edge(u, v)
        return self

    def annotate(self, predicate: Callable[[Node, Node, dict], dict]) -> "TaintGraph":
        """For every edge, merge the dict returned by ``predicate``
        into the edge's data. Use ``{}`` to leave an edge unchanged.
        Mutates ``self.g`` and returns ``self``."""
        for u, v, data in self.g.edges(data=True):
            extra = predicate(u, v, data)
            if extra:
                data.update(extra)
        return self

    # --- identity-flow subview ----------------------------------------

    def identity_subgraph(
        self,
        *,
        also_identity: Optional[Callable[["TaintGraph", Node, Node, dict], bool]] = None,
    ) -> "TaintGraph":
        """Return a new :class:`TaintGraph` containing only edges that
        are identity-preserving — i.e. the value at ``v`` equals the
        value at ``u`` after propagation.

        Default: edges whose ``kinds`` contains ``"identity"`` (the
        QL ``valueIdentityFlowStep`` channel).

        ``also_identity(graph, u, v, edge_data) -> bool`` is an
        optional Python hook that *promotes* extra edges to identity.
        The QL flow can't see things like ``concat("", x) == x``;
        write a small Python rule to recognise them. The hook is
        consulted only for edges that aren't already identity, so
        returning ``False`` is the no-op default.

        Example::

            def concat_with_empty(graph, u, v, data):
                if graph.op_of(v) != "concat":
                    return False
                a = graph._assignment_at(v)
                if a is None:
                    return False
                # concat with the empty bytes literal is identity on
                # the other operand.
                for inp in a.inputs:
                    cv = getattr(inp, "const_value", None)
                    if cv is not None and cv.kind == "bytes" and cv.value in ('""', "0x"):
                        return True
                return False

            id_g = g.identity_subgraph(also_identity=concat_with_empty)
        """
        keep: nx.DiGraph = nx.DiGraph()
        for n, attrs in self.g.nodes(data=True):
            keep.add_node(n, **attrs)
        for u, v, data in self.g.edges(data=True):
            kinds = data.get("kinds", set())
            is_id = "identity" in kinds
            if not is_id and also_identity is not None:
                is_id = bool(also_identity(self, u, v, data))
            if is_id:
                keep.add_edge(u, v, **data)
        return TaintGraph(g=keep, prog=self.prog)

    def _assignment_at(self, node: Node):
        """Look up the SSA :class:`Assignment` matching this node by
        ``(file, line)``. Convenience for ``also_identity`` rules."""
        for a in self.prog.assignments:
            if a.location.file == node.file and a.location.line == node.line:
                return a
        return None

    # --- DOT rendering ------------------------------------------------

    _COLOUR_PRIORITY = (
        ("callsub", "blue"),
        ("scratch", "purple"),
        ("identity", "black"),
        ("subroutine", "darkgreen"),
        ("broad", "orange"),
        ("generic", "gray"),
    )

    def to_dot(self) -> str:
        """Quick Graphviz dump for visual inspection. Each edge labelled
        with its set of kinds; coloured by the highest-priority kind
        the edge carries."""
        priority = {k: i for i, (k, _) in enumerate(self._COLOUR_PRIORITY)}
        colour = dict(self._COLOUR_PRIORITY)
        out = ["digraph TaintGraph {"]
        out.append('  node [shape=box, fontname="monospace"];')
        for n in self.g.nodes:
            out.append(f'  "{n!r}" [label="{n!r}"];')
        for u, v, data in self.g.edges(data=True):
            kinds = sorted(data.get("kinds", ()), key=lambda k: priority.get(k, 99))
            label = ",".join(kinds) if kinds else "?"
            extras = [
                f"{k}={val}"
                for k, val in data.items() if k != "kinds"
            ]
            if extras:
                label += " [" + ", ".join(extras) + "]"
            c = colour.get(kinds[0], "gray") if kinds else "gray"
            out.append(f'  "{u!r}" -> "{v!r}" [label="{label}", color="{c}"];')
        out.append("}")
        return "\n".join(out)


def _flow_rows_for(prog: SSAProgram) -> list[tuple]:
    """Read ``taintFlowEdges.csv`` from the per-DB cache. Falls back
    to running the query if the cache file is missing.

    Returns the rows as a list of tuples; empty list if the query
    produced no edges.
    """
    from ..graphs import _cache_dir_for, _read_csv, QUERIES_DIR, _run_csv_query

    db = Path(prog.db_path)
    cache = _cache_dir_for(db)
    csv_path = cache / "taintFlowEdges.csv"
    if not csv_path.exists():
        _run_csv_query(db, QUERIES_DIR / "taintFlowEdges.ql", cache)
    rows = _read_csv(csv_path)
    return [tuple(r) for r in rows]
