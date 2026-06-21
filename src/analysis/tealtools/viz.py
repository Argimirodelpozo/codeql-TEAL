"""Graphviz rendering for the loaded CFG graph.

Operates on the ``networkx`` graph returned by :func:`tealtools.graph.load_graph`
(AST nodes + ``kind="cfg"`` edges + per-node ``bb`` annotations). Two views:

- op-level: :func:`to_dot` / :func:`draw_cfg` — one node per opcode.
- basic-block level: :func:`cfg_bb_graph` + :func:`to_bb_dot` /
  :func:`draw_cfg_bb` — opcodes collapsed into BB boxes.

For the SSA *functional* view (``out = op(in)`` per assignment, with const /
range resolution), use :meth:`tealtools.ssa.SSAProgram.functional` /
``functional_by_block`` — those render the reconstructed SSA directly.
"""
from __future__ import annotations

from typing import Iterable

import networkx as nx

from .ast import AstNode, Location
from .dot import escape, render
from .control_tree import (
    Region, BlockR, SequenceR, IfR, IfElseR, GuardR,
    SwitchR, LoopR, ImproperR, ProgramR,
)


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

_CFG_EDGE_STYLES = {
    "NormalSuccessor":           "",
    "BooleanSuccessor(true)":    'color="#2a8f3c", fontcolor="#2a8f3c", label="T"',
    "BooleanSuccessor(false)":   'color="#c0392b", fontcolor="#c0392b", label="F"',
    "ConditionalJumpCompletion(true)":  'color="#2a8f3c", fontcolor="#2a8f3c", label="T"',
    "ConditionalJumpCompletion(false)": 'color="#c0392b", fontcolor="#c0392b", label="F"',
    "UnconditionalJumpCompletion":      'style=bold, label="jmp"',
    "RetsubCompletion":          'style=dashed, label="retsub"',
    "MultilabelJumpCompletion":  'style=dotted',
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
    """Emit Graphviz DOT for the op-level CFG. ``file`` optionally restricts
    to one source file; nodes are labeled ``<line>: <opcode>``."""
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
    """Return a CFG graph with every basic block collapsed into one node.

    Output nodes are :class:`BasicBlockNode` instances (carrying the ordered
    list of AST nodes inside). Inter-BB CFG edges are kept with their original
    ``successor`` label; intra-BB straight-line edges are collapsed. Requires
    that ``load_graph`` annotated every AST node with a ``bb`` attribute.
    """
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
    return "\\l".join([header, ""] + body_lines) + "\\l"


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
            f'label="{escape(_bb_label(n))}", '
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
    """Render the CFG at basic-block granularity. Accepts either the op-level
    graph (collapsed internally) or a pre-built BB graph from
    :func:`cfg_bb_graph`."""
    h = g if any(isinstance(n, BasicBlockNode) for n in g.nodes) else cfg_bb_graph(g)
    return render(
        to_bb_dot(h, file=file, rankdir=rankdir),
        format=format, engine=engine,
    )

# ---------------------------------------------------------------------------
# Control-tree (region) DOT / Mermaid rendering
# ---------------------------------------------------------------------------


def region_to_dot(region: Region, *, nested: bool = True) -> str:
    """Render the control tree as a Graphviz DOT string.

    ``nested=True`` (default): each non-leaf region is a cluster
    (subgraph) containing its children — useful for *seeing* the
    decomposition. Leaf blocks show their op list. Sibling clusters
    don't carry CFG edges; ordering within a ``SequenceR`` is shown
    via dashed arrows so flow direction is visible.

    ``nested=False``: a pure parent-child tree where every region
    is its own node and edges are labelled by role (``"then"``,
    ``"body"``, ``"case 2"``, etc.). Easier to read for very
    deeply nested structures.

    Render with: ``dot -Tsvg tree.dot -o tree.svg`` or paste into
    https://dreampuf.github.io/GraphvizOnline.
    """
    if nested:
        return _to_dot_nested(region)
    return _to_dot_tree(region)


def _short_label(s: str) -> str:
    """Escape a string for use inside a Graphviz label."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _block_label(region: BlockR) -> str:
    # Escape each line's text individually, then join with literal
    # ``\l`` (Graphviz's left-align line break) — keep those unescaped
    # so they survive into the DOT output.
    parts = [
        _short_label(f"L{a.location.line:>3} {a.op}")
        for a in region.bb.assignments
    ]
    return "\\l".join(parts) + "\\l"


def _to_dot_nested(root: Region) -> str:
    """Nested-cluster rendering. Each non-leaf region is a cluster
    containing its children; the cluster's label shows the region
    kind. Sequences carry dashed-arrow ordering edges."""
    lines: list[str] = [
        "digraph ControlTree {",
        "  compound=true;",
        '  node [shape=box, fontname="monospace", fontsize=10];',
        '  edge [fontname="monospace", fontsize=9];',
        "  graph [labeljust=l, labelloc=t, style=rounded];",
    ]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def emit(region: Region, depth: int) -> tuple[str, str]:
        """Return ``(anchor_id, last_id)`` — the anchor we use for
        inter-cluster edges (the cluster name for non-leaves, the
        node id for leaves) and the same id again for symmetry."""
        pad = "  " * (depth + 1)
        if isinstance(region, BlockR):
            nid = fresh()
            lines.append(f'{pad}{nid} [label="{_block_label(region)}"];')
            return nid, nid
        cluster = f"cluster_{fresh()}"
        lines.append(f"{pad}subgraph {cluster} {{")
        kind_label = region.kind
        if isinstance(region, LoopR):
            kind_label = f"loop ({len(region.loop.nodes)} bbs, "
            kind_label += "reducible" if region.loop.is_reducible() else "irreducible"
            kind_label += ")"
        elif isinstance(region, ImproperR):
            kind_label = f"improper ({len(region.nodes)} nodes)"
        elif isinstance(region, SwitchR):
            kind_label = f"switch ({len(region.cases)} cases)"
        lines.append(f'{pad}  label="{kind_label}";')
        lines.append(f"{pad}  style=rounded;")
        lines.append(f"{pad}  color={_color_for(region)};")
        # Emit children and remember their anchors for intra-cluster wiring.
        anchors: list[str] = []
        for c in region.children():
            anchor, _ = emit(c, depth + 1)
            anchors.append(anchor)
        # Sequence: dashed-arrow chain through children.
        if isinstance(region, SequenceR) and len(anchors) >= 2:
            for a, b in zip(anchors, anchors[1:]):
                lines.append(f'{pad}  {a} -> {b} [style=dashed, arrowhead=open];')
        lines.append(f"{pad}}}")
        # Pick a stable representative inside the cluster so callers
        # wanting to draw an edge to the whole thing have a target.
        return anchors[0] if anchors else fresh(), cluster

    emit(root, 0)
    lines.append("}")
    return "\n".join(lines)


def _to_dot_tree(root: Region) -> str:
    """Parent-child rendering. Each region (including non-leaves) is
    its own node; edges are labelled by role."""
    lines: list[str] = [
        "digraph ControlTree {",
        "  rankdir=TB;",
        '  node [shape=box, fontname="monospace", fontsize=10];',
        '  edge [fontname="monospace", fontsize=9];',
    ]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def emit(region: Region) -> str:
        nid = fresh()
        color = _color_for(region)
        if isinstance(region, BlockR):
            lines.append(
                f'  {nid} [label="block\\l{_block_label(region)}", '
                f'color={color}];'
            )
            return nid
        # Non-leaf with summary label.
        if isinstance(region, SequenceR):
            label = f"sequence\\n({len(region.parts)} parts)"
        elif isinstance(region, LoopR):
            label = (
                f"loop\\n({len(region.loop.nodes)} bbs, "
                + ("reducible" if region.loop.is_reducible() else "irreducible")
                + ")"
            )
        elif isinstance(region, SwitchR):
            label = f"switch\\n({len(region.cases)} cases)"
        elif isinstance(region, ImproperR):
            label = f"improper\\n({len(region.nodes)} nodes)"
        else:
            label = region.kind
        lines.append(f'  {nid} [label="{label}", color={color}];')
        # Emit role-labelled child edges.
        if isinstance(region, SequenceR):
            for i, c in enumerate(region.parts):
                cid = emit(c)
                lines.append(f'  {nid} -> {cid} [label="{i}"];')
        elif isinstance(region, IfR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.then_branch)} [label="then"];')
        elif isinstance(region, IfElseR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.then_branch)} [label="then"];')
            lines.append(f'  {nid} -> {emit(region.else_branch)} [label="else"];')
        elif isinstance(region, GuardR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.exit_arm)} [label="exit"];')
        elif isinstance(region, SwitchR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            for i, c in enumerate(region.cases):
                lines.append(f'  {nid} -> {emit(c)} [label="case {i}"];')
        elif isinstance(region, LoopR):
            lines.append(f'  {nid} -> {emit(region.body)} [label="body"];')
        elif isinstance(region, ImproperR):
            for i, c in enumerate(region.nodes):
                lines.append(f'  {nid} -> {emit(c)} [label="{i}"];')
        elif isinstance(region, ProgramR):
            for i, p in enumerate(region.programs):
                lines.append(f'  {nid} -> {emit(p)} [label="prog {i}"];')
        return nid

    emit(root)
    lines.append("}")
    return "\n".join(lines)


def _color_for(region: Region) -> str:
    """Per-kind border colour, makes the kinds easy to skim in DOT."""
    return {
        "block": "gray60",
        "sequence": "black",
        "if": "darkblue",
        "ifelse": "darkblue",
        "switch": "purple",
        "guard": "darkgreen",
        "loop": "darkorange",
        "improper": "red",
        "program": "navy",
    }.get(region.kind, "black")


def region_to_mermaid(region: Region) -> str:
    """Render the control tree as a Mermaid ``flowchart`` source —
    handy for inlining in markdown / Jupyter where Graphviz isn't
    available. Produces a parent-child tree mirroring
    :func:`_to_dot_tree`."""
    lines: list[str] = ["flowchart TD"]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def safe(s: str) -> str:
        return s.replace('"', "'").replace("\n", "<br/>")

    def emit(region: Region) -> str:
        nid = fresh()
        if isinstance(region, BlockR):
            ops = "<br/>".join(
                f"L{a.location.line} {a.op}" for a in region.bb.assignments
            )
            lines.append(f'  {nid}["block<br/>{safe(ops)}"]')
            return nid
        if isinstance(region, SequenceR):
            lines.append(f'  {nid}(["sequence ({len(region.parts)} parts)"])')
            for i, c in enumerate(region.parts):
                lines.append(f"  {nid} -- {i} --> {emit(c)}")
        elif isinstance(region, IfR):
            lines.append(f'  {nid}{{"if"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- then --> {emit(region.then_branch)}")
        elif isinstance(region, IfElseR):
            lines.append(f'  {nid}{{"ifelse"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- then --> {emit(region.then_branch)}")
            lines.append(f"  {nid} -- else --> {emit(region.else_branch)}")
        elif isinstance(region, GuardR):
            lines.append(f'  {nid}{{"guard"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- exit --> {emit(region.exit_arm)}")
        elif isinstance(region, SwitchR):
            lines.append(f'  {nid}{{"switch ({len(region.cases)} cases)"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            for i, c in enumerate(region.cases):
                lines.append(f"  {nid} -- case{i} --> {emit(c)}")
        elif isinstance(region, LoopR):
            kind = "reducible" if region.loop.is_reducible() else "irreducible"
            lines.append(
                f'  {nid}[/"loop ({len(region.loop.nodes)} bbs, {kind})"\\]'
            )
            lines.append(f"  {nid} -- body --> {emit(region.body)}")
        elif isinstance(region, ImproperR):
            lines.append(f'  {nid}["improper ({len(region.nodes)} nodes)"]')
            for i, c in enumerate(region.nodes):
                lines.append(f"  {nid} -- {i} --> {emit(c)}")
        elif isinstance(region, ProgramR):
            lines.append(f'  {nid}[["programs ({len(region.programs)})"]]')
            for i, p in enumerate(region.programs):
                lines.append(f"  {nid} -- prog{i} --> {emit(p)}")
        return nid

    emit(region)
    return "\n".join(lines)
