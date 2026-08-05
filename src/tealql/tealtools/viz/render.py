"""Graphviz rendering for the loaded CFG graph (AST nodes + ``kind="cfg"`` edges +
per-node ``bb`` annotations), at op level (:func:`to_dot`) or with opcodes
collapsed into BB boxes (:func:`cfg_bb_graph` + :func:`to_bb_dot`), plus the
control-tree region renderers.
"""
from __future__ import annotations

from typing import Iterable

import networkx as nx

from .. import cfg_build as _cfg_build
from ..ast import AstNode, Location
from .._utils.dot import escape, render
class BasicBlockNode:
    """A basic block as a single node in the BB-collapsed CFG view."""

    __slots__ = ("file", "first_line", "last_line", "ast_nodes", "phis")

    def __init__(self, file: str, first_line: int, last_line: int):
        self.file = file
        self.first_line = first_line
        self.last_line = last_line
        self.ast_nodes: list = []
        self.phis: list = []

    @property
    def location(self) -> Location:
        return Location(self.file, self.first_line, 0, self.last_line, 0)

    def _key(self) -> tuple:
        return (self.file, self.first_line, self.last_line)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, BasicBlockNode) and self._key() == other._key()

    def __repr__(self) -> str:
        return f"BBNode({self.file}:{self.first_line}-{self.last_line})"


def _edges_of_kind(g: nx.MultiDiGraph, kind: str) -> Iterable[tuple]:
    for u, v, k, d in g.edges(keys=True, data=True):
        if d.get("kind") == kind:
            yield u, v, k


def cfg_view(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Read-only edge-subgraph containing only CFG edges and their endpoints."""
    return g.edge_subgraph(_edges_of_kind(g, "cfg"))


# -- Graphviz rendering -------------------------------------------------------

#: Keyed by the successor labels :mod:`..cfg_build` actually emits — imported,
#: not respelled, so a label change cannot silently fall through to the
#: `label="<raw>"` default below. The other five keys here
#: (``*JumpCompletion``, ``RetsubCompletion``) were CodeQL completion classes
#: that no producer has emitted since the extractor became pure Python.
_CFG_EDGE_STYLES = {
    _cfg_build.NORMAL:     "",
    _cfg_build.BOOL_TRUE:  'color="#2a8f3c", fontcolor="#2a8f3c", label="T"',
    _cfg_build.BOOL_FALSE: 'color="#c0392b", fontcolor="#c0392b", label="F"',
}


def _dot_id(n) -> str:
    return '"' + escape(f"{n.location.file}:{n.location.start_line}") + '"'


def _edge_attrs(data: dict) -> str:
    if data.get("kind") == "cfg":
        succ = data.get("successor", "")
        style = _CFG_EDGE_STYLES.get(succ)
        if style is not None:
            return style
        return f'label="{escape(succ)}"'
    return ""


def to_dot(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    rankdir: str = "TB",
) -> str:
    """Emit Graphviz DOT for the op-level CFG, one node per opcode labeled
    ``<line>: <opcode>``; ``file`` restricts to one source file."""
    nodes = [n for n in g.nodes if file is None or n.location.file == file]
    node_set = set(nodes)

    lines = [
        "digraph TEAL {",
        f"  rankdir={rankdir};",
        "  overlap=false;",
        "  splines=true;",
        '  node [shape=box, fontname="Monospace", fontsize=10];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    for n in sorted(nodes, key=lambda x: (x.location.file, x.location.start_line)):
        body = n.code or n.node_class
        label = f"{n.location.start_line}: {body}"
        lines.append(f'  {_dot_id(n)} [label="{escape(label)}"];')

    for u, v, _, data in g.edges(keys=True, data=True):
        if data.get("kind") != "cfg":
            continue
        if u not in node_set or v not in node_set:
            continue
        attrs = _edge_attrs(data)
        sep = " " if attrs else ""
        lines.append(f"  {_dot_id(u)} -> {_dot_id(v)}{sep}[{attrs}];")

    lines.append("}")
    return "\n".join(lines)


def draw_cfg(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render the op-level CFG as a layered DOT graph (Jupyter-renderable SVG)."""
    return render(
        to_dot(g, file=file, rankdir=rankdir),
        format=format, engine=engine,
    )


# -- Basic-block view ---------------------------------------------------------


def cfg_bb_graph(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """A CFG graph with every basic block collapsed into one :class:`BasicBlockNode`,
    keeping inter-BB edges with their ``successor`` label; requires the per-node
    ``bb`` annotation ``load_graph`` adds."""
    bb_cache: dict[tuple, BasicBlockNode] = {}

    def _bb_for_ast(n: AstNode) -> BasicBlockNode | None:
        bb_id = g.nodes[n].get("bb")
        if bb_id is None:
            return None
        bb = bb_cache.get(bb_id)
        if bb is None:
            bb = BasicBlockNode(*bb_id)
            bb_cache[bb_id] = bb
        return bb

    for n in g.nodes:
        if isinstance(n, AstNode):
            bb = _bb_for_ast(n)
            if bb is not None:
                bb.ast_nodes.append(n)
    for bb in bb_cache.values():
        bb.ast_nodes.sort(key=lambda x: x.location.start_line)

    h = nx.MultiDiGraph()
    h.graph.update(g.graph)
    for bb in bb_cache.values():
        h.add_node(bb)

    for u, v, data in g.edges(data=True):
        if data.get("kind") != "cfg":
            continue
        succ = data.get("successor")
        u2 = _bb_for_ast(u)
        v2 = _bb_for_ast(v)
        if u2 is None or v2 is None:
            continue
        if u2 is v2:  # collapse intra-BB straight-line edges
            continue
        h.add_edge(u2, v2, kind="cfg", successor=succ)

    return h


def _bb_label(bb: BasicBlockNode, *, max_lines: int = 20) -> str:
    header = f"BB L{bb.first_line}-L{bb.last_line}"
    body_lines = [
        f"{n.location.start_line}: {n.code or n.node_class}"
        for n in bb.ast_nodes
    ]
    if len(body_lines) > max_lines:
        elided = len(body_lines) - (max_lines - 1)
        body_lines = body_lines[: max_lines - 1] + [f"... (+{elided} more)"]
    # Escape each part, THEN join with the literal ``\l`` (Graphviz left-align);
    # escaping the joined result doubles the separators' backslashes.
    return "\\l".join(escape(p) for p in [header, ""] + body_lines) + "\\l"


def _bb_dot_id(bb: BasicBlockNode) -> str:
    suffix = f"#{bb.first_line}-{bb.last_line}"
    return '"' + escape(f"BB:{bb.file}{suffix}") + '"'


def to_bb_dot(
    h: nx.MultiDiGraph,
    *,
    file: str | None = None,
    rankdir: str = "TB",
) -> str:
    """Emit DOT for a BB-collapsed CFG graph (from :func:`cfg_bb_graph`)."""
    nodes = [n for n in h.nodes if file is None or n.file == file]
    node_set = set(nodes)

    lines = [
        "digraph TEAL_BB {",
        f"  rankdir={rankdir};",
        "  overlap=false;",
        "  splines=true;",
        '  node [shape=box, fontname="Monospace", fontsize=9];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    for n in sorted(nodes, key=lambda bb: (bb.file, bb.first_line)):
        attrs = (
            f'label="{_bb_label(n)}", '   # already escaped part-wise (keeps \l breaks)
            'shape=box, style="rounded,filled", fillcolor="#f4f4f8"'
        )
        lines.append(f"  {_bb_dot_id(n)} [{attrs}];")

    for u, v, data in h.edges(data=True):
        if u not in node_set or v not in node_set:
            continue
        if data.get("kind") != "cfg":
            continue
        attrs = _edge_attrs(data)
        sep = " " if attrs else ""
        lines.append(f"  {_bb_dot_id(u)} -> {_bb_dot_id(v)}{sep}[{attrs}];")

    lines.append("}")
    return "\n".join(lines)


def draw_cfg_bb(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render the CFG at basic-block granularity, from either the op-level graph
    (collapsed internally) or a pre-built BB graph."""
    h = g if any(isinstance(n, BasicBlockNode) for n in g.nodes) else cfg_bb_graph(g)
    return render(
        to_bb_dot(h, file=file, rankdir=rankdir),
        format=format, engine=engine,
    )

# ---------------------------------------------------------------------------
# Control-tree (region) DOT / Mermaid rendering
# ---------------------------------------------------------------------------
