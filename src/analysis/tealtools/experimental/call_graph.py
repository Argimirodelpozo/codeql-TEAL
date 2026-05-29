"""Subroutine call-graph extraction + Graphviz rendering.

Each node is a subroutine (its entry BB) labelled with its static
``(cost, submits)`` summary. Each edge is a ``callsub`` site — for
each caller→callee pair we count call-site frequency and label the
edge accordingly. The result is a small DAG (or a graph-with-cycles
if recursion is present — see :mod:`recursion`).

The main program(s) are added as synthetic nodes named ``main_<n>``;
they're rooted by ``callsub`` ops that target subroutines.

Usage::

    from tealtools.experimental.call_graph import to_dot
    print(to_dot(prog))   # paste into Graphviz
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import networkx as nx

from ..control_tree import (
    BlockR, ProgramR, build_control_tree,
)
from ..ssa import BasicBlock, SSAProgram


@dataclass(frozen=True)
class CallEdge:
    caller: object   # BasicBlock for sub, or str "main_N" for main
    callee: BasicBlock
    count: int       # number of distinct callsub sites of `callee` in `caller`


def build(prog: SSAProgram) -> tuple[nx.DiGraph, dict]:
    """Build the call graph.

    Returns ``(graph, summaries)``:
    - ``graph``: nx.DiGraph. Subroutine nodes are :class:`BasicBlock`
      entries; main-program nodes are ``"main_<i>"`` strings. Edges
      carry a ``"count"`` attribute.
    - ``summaries``: ``entry_bb → (cost, submits)``.
    """
    tree = build_control_tree(prog)
    g = nx.DiGraph()
    summaries: dict = {}

    if not isinstance(tree, ProgramR):
        return g, summaries

    summaries = dict(tree.subroutine_summaries)
    for entry_bb in tree.subroutines:
        g.add_node(entry_bb, cost=summaries.get(entry_bb, (0, 0))[0],
                   submits=summaries.get(entry_bb, (0, 0))[1])

    # Edges from subroutine to subroutine.
    for entry_bb, body_region in tree.subroutines.items():
        callees = Counter()
        for r in body_region.walk():
            if not isinstance(r, BlockR):
                continue
            bb = r.bb
            if (
                bb.assignments
                and bb.assignments[-1].op == "callsub"
                and bb.successors
                and bb.successors[0] in tree.subroutines
            ):
                callees[bb.successors[0]] += 1
        for callee, count in callees.items():
            g.add_edge(entry_bb, callee, count=count)

    # Synthetic main-program nodes, and edges from each to its callees.
    for i, main_region in enumerate(tree.programs):
        main_id = f"main_{i}"
        g.add_node(main_id, cost=0, submits=0, kind="main")
        callees = Counter()
        for r in main_region.walk():
            if not isinstance(r, BlockR):
                continue
            bb = r.bb
            if (
                bb.assignments
                and bb.assignments[-1].op == "callsub"
                and bb.successors
                and bb.successors[0] in tree.subroutines
            ):
                callees[bb.successors[0]] += 1
        for callee, count in callees.items():
            g.add_edge(main_id, callee, count=count)

    return g, summaries


def to_dot(prog: SSAProgram) -> str:
    """Render the call graph as a Graphviz DOT string. Subroutine
    nodes are labelled with their entry line + cost + submits;
    main-program nodes get a distinct shape."""
    g, summaries = build(prog)
    lines: list[str] = [
        "digraph CallGraph {",
        "  rankdir=LR;",
        '  node [fontname="monospace", fontsize=10];',
        '  edge [fontname="monospace", fontsize=9];',
    ]

    def node_id(n) -> str:
        if isinstance(n, str):
            return n
        # BasicBlock — synth a stable name from file+line.
        loc = n.assignments[0].location if n.assignments else None
        if loc:
            tag = f"{loc.file.replace('/', '_').replace('.', '_')}_L{loc.line}"
        else:
            tag = f"bb_{id(n)}"
        return f"sub_{tag}"

    for n in g.nodes:
        if isinstance(n, str):
            # Main program node.
            lines.append(
                f'  {n} [shape=doublecircle, style=filled, '
                f'fillcolor=lightblue, label="{n}"];'
            )
        else:
            cost, submits = summaries.get(n, (0, 0))
            if n.assignments:
                loc = n.assignments[0].location
                label_file = loc.file.split("/")[-1]
                label = f"{label_file}\\nL{loc.line}\\ncost={cost} subs={submits}"
            else:
                label = f"<bb>\\ncost={cost} subs={submits}"
            # Size by cost (log scale) — clamp to readable range.
            import math
            size = max(0.5, min(2.5, math.log10(max(1, cost)) * 0.5))
            lines.append(
                f'  {node_id(n)} [shape=box, style=rounded, '
                f'width={size:.2f}, label="{label}"];'
            )
    for u, v, data in g.edges(data=True):
        count = data.get("count", 1)
        label = f"×{count}" if count > 1 else ""
        attrs = []
        if label:
            attrs.append(f'label="{label}"')
        attrs.append(f"penwidth={min(4.0, 0.8 + 0.4 * count):.1f}")
        attr_str = ", ".join(attrs)
        lines.append(f"  {node_id(u)} -> {node_id(v)} [{attr_str}];")
    lines.append("}")
    return "\n".join(lines)
