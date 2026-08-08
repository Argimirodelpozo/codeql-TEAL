"""Coarse taint-flow graph over ``(file, line, node_class)`` nodes, built from the
PySSA def-use relation plus the scratch and frame-param bridges.

Nodes are LINE-granular, so every value produced on a TEAL line collapses into
one node — reachability here is a lenient superset, which is what the refiners
prune down."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional

import networkx as nx

from ._nx_view import NxGraphView

from ..ssa import SSAProgram


@dataclass(frozen=True)
class Node:
    """A dataflow node, identified by ``(file, line, node_class)``."""

    file: str
    line: int
    node_class: str

    def __repr__(self) -> str:
        return f"{self.node_class}@{self.file}:L{self.line}"


@dataclass
class TaintGraph(NxGraphView):
    """Graph wrapper with a refinement API; one edge per ``(src, dst)`` pair,
    with every contributing channel collapsed into its ``kinds`` set."""

    g: nx.DiGraph
    prog: SSAProgram

    @classmethod
    def of(cls, prog: SSAProgram) -> "TaintGraph":
        """Build the graph, annotating each node with its TEAL opcode.

        The opcode annotation is what ``find(op=…)`` matches on, because
        ``node_class`` is sometimes a parent class (``ZeroArgumentOpcode`` for
        ``box_create``) and cannot identify the op."""
        # So node-level value annotations include phi unification and folds.
        prog.propagate_constants()

        # (file, line) → (op, immediates, const_values), each const_value a
        # ``(kind, value)`` with ``kind`` ∈ ``{"int", "bytes"}``.
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
            src = Node(file=sf, line=int(sl), node_class=sc)
            dst = Node(file=df, line=int(dl), node_class=dc)
            _add(src)
            _add(dst)
            if g.has_edge(src, dst):
                g[src][dst]["kinds"].add(kind)
            else:
                g.add_edge(src, dst, kinds={kind})
        return cls(g=g, prog=prog)

    def const_values_at(self, node: Node) -> tuple[tuple[str, str], ...]:
        """The ``(kind, value)`` literals this node is known to produce, if any."""
        if node not in self.g:
            return ()
        return self.g.nodes[node].get("const_values") or ()

    def is_const_at(self, node: Node) -> bool:
        """True iff EVERY output of this op is a known literal.

        HAZARD: used as a pruning predicate, so it must require all outputs. A
        node with one folded output and one runtime output still emits taint."""
        cvs = self.const_values_at(node)
        if not cvs:
            return False
        a = self._assignment_at(node)
        if a is None:
            return False
        return len(cvs) == len(a.outputs)

    # --- queries ------------------------------------------------------

    def edges(self) -> Iterator[tuple[Node, Node, dict]]:
        for u, v, data in self.g.edges(data=True):
            yield u, v, data

    def edges_by_kind(self) -> dict[str, int]:
        """Edge count per kind; a multi-kind edge counts once per kind."""
        out: dict[str, int] = defaultdict(int)
        for _, _, data in self.g.edges(data=True):
            for k in data.get("kinds", ()):
                out[k] += 1
        return dict(out)

    def edges_with_kind(self, kind: str) -> Iterator[tuple[Node, Node, dict]]:
        """Iterate the edges to which ``kind`` contributed."""
        for u, v, data in self.g.edges(data=True):
            if kind in data.get("kinds", ()):
                yield u, v, data

    def predecessors(self, node: Node) -> list[Node]:
        return list(self.g.predecessors(node))

    def successors(self, node: Node) -> list[Node]:
        return list(self.g.successors(node))

    def paths(
        self,
        src: Node,
        dst: Node,
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[Node]]:
        """Simple paths ``src`` to ``dst``, shortest-first, capped at ``max_paths``."""
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
        node_class: Optional[str] = None,
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> list[Node]:
        """Node lookup by any combination of op / immediates / class / file / line.

        HAZARD: all-None returns EVERY node, so a caller passing only optional
        filters can silently select the whole program."""
        out: list[Node] = []
        for n in self.g.nodes:
            attrs = self.g.nodes[n]
            if node_class is not None and n.node_class != node_class:
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
        """Simple paths from any ``srcs`` node to any ``dsts`` node, shortest-first,
        capped at ``max_paths`` across ALL pairs."""
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
        """Drop every edge the predicate accepts; MUTATES ``self.g``, returns self."""
        to_drop: list[tuple[Node, Node]] = [
            (u, v) for u, v, data in self.g.edges(data=True)
            if predicate(u, v, data)
        ]
        for u, v in to_drop:
            self.g.remove_edge(u, v)
        return self

    def annotate(self, predicate: Callable[[Node, Node, dict], dict]) -> "TaintGraph":
        """Merge each edge with the predicate's dict; MUTATES ``self.g``, returns self."""
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
        """A new graph of only identity-preserving edges — the value at ``v``
        equals the value at ``u``.

        ``also_identity(graph, u, v, data) -> bool`` promotes extra edges the
        base flow cannot see (``concat("", x) == x``); it is consulted only for
        edges not already identity."""
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
        """The SSA :class:`Assignment` at this node's ``(file, line)``."""
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
        """Graphviz dump, each edge labelled by kind and coloured by its highest."""
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


# Only ``ssa-step`` and ``identity`` drive a refiner; the rest are cosmetic
# graph colours, emitted as a lenient superset.
_DEFUSE_KINDS = ("ssa-step", "subroutine", "generic", "broad")
# A phi argument flows into the phi unchanged: an identity step.
_PHIARG_KINDS = ("phi-arg", "identity", "ssa-step", "subroutine")
# A scratch store's value reaches the matching load unchanged.
_SCRATCH_KINDS = ("scratch", "ssa-step", "subroutine")
# A caller arg reaches the callee's frame_dig param read (interprocedural).
_FRAME_KINDS = ("frame", "ssa-step", "subroutine")


def _flow_rows_for(prog: SSAProgram) -> list[tuple]:
    """Coarse taint-flow rows ``(srcFile, srcLine, srcClass, sinkFile, sinkLine,
    sinkClass, kind)``.

    Four edge sources: def-use (``ssa-step``), phi args (``identity``), scratch
    ``store`` to ``load`` (``scratch``), and caller arg to callee ``frame_dig``
    (``frame``). PySSA already resolves cross-block and stack-shuffle flow into
    direct def-use; the frame rows add the cross-subroutine flow it omits."""
    from ..ssa.models import Phi, SSAVar

    # The scratch rows read a lazily-computed annotation; trigger it up front.
    prog._ensure_scratch_influence()
    g = getattr(prog, "_graph", None)
    cls_at: dict[tuple[str, int], str] = {}
    if g is not None:
        for n in g.nodes:
            loc = n.location
            cls_at[(loc.file, loc.start_line)] = n.node_class

    rows: list[tuple] = []

    def _node(operand):
        """``(file, line, class)`` for a defined operand; ``None`` for a
        constant, which is a natural taint stopper."""
        if isinstance(operand, Phi):
            return operand.file, operand.line, "Phi"
        if isinstance(operand, SSAVar):
            f, ln = operand.file, operand.line
            return f, ln, cls_at.get((f, ln), operand.__class__.__name__)
        return None  # Const / unresolved

    def _emit(src, df: str, dl: int, dc: str, kinds) -> None:
        if src is None:
            return
        for k in kinds:
            rows.append((src[0], src[1], src[2], df, dl, dc, k))

    # def-use: each input's definition flows to the op consuming it.
    for a in prog.assignments:
        df, dl = a.location.file, a.location.line
        dc = cls_at.get((df, dl), a.op)
        for inp in a.inputs:
            _emit(_node(inp), df, dl, dc, _DEFUSE_KINDS)

    # phi-arg: every incoming def flows into the phi (value-identity step).
    phis = getattr(prog, "phis", None)
    for ph in (phis.values() if isinstance(phis, dict) else (phis or ())):
        df, dl = ph.file, ph.line
        for arg in getattr(ph, "args", ()):
            _emit(_node(arg), df, dl, "Phi", _PHIARG_KINDS)

    # scratch bridge: a `store N`-d value reaches each `load N` of that slot.
    if g is not None:
        for n in g.nodes:
            stores = g.nodes[n].get("scratch_stores")
            if not stores:
                continue
            loc = n.location
            dc = cls_at.get((loc.file, loc.start_line), "?")
            for sk in stores:
                sf, sl = sk[0], sk[1]
                _emit((sf, sl, cls_at.get((sf, sl), "?")),
                      loc.file, loc.start_line, dc, _SCRATCH_KINDS)

    # Frame sources already represented by normal SSA edges are emitted above;
    # add only compatibility gaps here.
    from ..passes.frame_flow import frame_gap_sources
    for dig_out, args in frame_gap_sources(prog).items():
        dst = _node(dig_out)
        if dst is None:
            continue
        for arg in args:
            _emit(_node(arg), dst[0], dst[1], dst[2], _FRAME_KINDS)

    return rows
