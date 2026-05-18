"""SCC-based loop detection and per-loop static summaries.

Consumes :class:`SSAProgram` and produces a :class:`LoopForest` — every
strongly-connected component containing a cycle, plus the inclusion
(nesting) tree among them, plus per-loop body-DAG summaries.

Why SCCs and not natural loops:
The natural-loop algorithm (back-edge + dominator) only recognises
*reducible* CFGs. Real TEAL output, especially after compiler
optimisations, can produce SCCs that aren't single-header (irreducible
control flow, multi-entry cycles, etc.). Using SCCs directly lets us
treat every cycle region uniformly: collapse it into a per-iteration
summary regardless of how it was structured.

What each :class:`Loop` carries:

- ``nodes``: the SCC's BBs.
- ``entries``: BBs in the SCC with at least one predecessor outside the
  SCC — these are the points control can flow *into* the loop. Their
  count tells you whether the loop is single-header (reducible-style)
  or multi-header (irreducible).
- ``back_edges``: edges within the SCC that, if removed, leave the
  remaining within-SCC edges acyclic (the "body DAG"). Computed by
  removing one edge per cycle until the result is acyclic — networkx's
  :func:`feedback_arc_set` semantics. We use a deterministic greedy:
  for each entry, walk the SCC in topological order using the body DAG;
  edges that would form a cycle become back-edges.
- ``body_dag_edges``: the within-SCC edges that are NOT back-edges. A
  DAG over ``nodes``.

The :class:`LoopForest` exposes inside-out iteration so consumers can
summarise innermost loops first (their summary becomes a compound op
attributed to the loop's entry node in the outer-loop body DAG).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

import networkx as nx

from .ssa import BasicBlock, SSAProgram


@dataclass
class Loop:
    """One cycle region (a non-trivial SCC)."""

    nodes: set[BasicBlock]
    entries: set[BasicBlock]
    back_edges: set[tuple[BasicBlock, BasicBlock]]
    body_dag_edges: set[tuple[BasicBlock, BasicBlock]]

    def exits(self) -> set[BasicBlock]:
        """BBs outside ``nodes`` that are direct successors of some
        body BB — where execution lands when the loop terminates."""
        out: set[BasicBlock] = set()
        for bb in self.nodes:
            for s in bb.successors:
                if s not in self.nodes:
                    out.add(s)
        return out

    def is_nested_inside(self, other: "Loop") -> bool:
        """True when this loop's nodes are a strict subset of
        ``other``'s — i.e. this loop sits inside that one."""
        return self is not other and self.nodes < other.nodes

    def is_reducible(self) -> bool:
        """True iff there's exactly one entry — a single header."""
        return len(self.entries) == 1


@dataclass
class LoopForest:
    """All loops in a program, plus the nesting tree."""

    loops: list[Loop]
    # parent[loop_idx] = idx of immediate-enclosing loop, or None.
    parents: dict[int, Optional[int]]
    # Map BB → idx of its innermost containing loop, if any.
    innermost: dict[BasicBlock, int]

    def innermost_first(self) -> Iterator[Loop]:
        """Iterate loops innermost-first (leaves of nesting tree
        before their ancestors). Order within a level is by
        construction order."""
        # Order by depth descending: a loop's depth = chain length to root.
        depth: dict[int, int] = {}

        def d(i: int) -> int:
            if i in depth:
                return depth[i]
            p = self.parents.get(i)
            depth[i] = 0 if p is None else d(p) + 1
            return depth[i]

        order = sorted(range(len(self.loops)), key=d, reverse=True)
        for i in order:
            yield self.loops[i]

    def loop_of(self, bb: BasicBlock) -> Optional[Loop]:
        """Innermost loop containing ``bb``, or None."""
        i = self.innermost.get(bb)
        return self.loops[i] if i is not None else None


def find_loops(prog: SSAProgram, *, graph: Optional[nx.DiGraph] = None) -> LoopForest:
    """Build a :class:`LoopForest` for ``prog``'s CFG. Uses networkx
    SCC + greedy back-edge selection (no dominators needed, so this
    handles irreducible regions too).

    Pass ``graph`` to run loop detection on an alternative CFG view
    (e.g. with interprocedural ``callsub``/``retsub`` edges removed,
    so cross-sub recursion / mutual-call cycles aren't misclassified
    as loops). Must be a BB→BB :class:`nx.DiGraph` over ``prog.blocks``."""
    g = graph if graph is not None else _build_cfg_graph(prog)
    loops: list[Loop] = []
    for scc_nodes in nx.strongly_connected_components(g):
        if len(scc_nodes) == 1:
            (only,) = scc_nodes
            # Trivial unless self-loop.
            if not g.has_edge(only, only):
                continue
        scc = set(scc_nodes)
        entries = {n for n in scc if any(p not in scc for p in n.predecessors)}
        if not entries:
            # Unreachable cycle (no entry from outside the SCC). Pick
            # any node as a conventional entry so back-edge selection
            # has somewhere to start.
            entries = {next(iter(scc))}
        back_edges, body_dag = _select_back_edges(g, scc, entries)
        loops.append(Loop(
            nodes=scc,
            entries=entries,
            back_edges=back_edges,
            body_dag_edges=body_dag,
        ))

    # Build nesting tree: parent of L = the smallest enclosing loop, or
    # None if L is top-level.
    parents: dict[int, Optional[int]] = {}
    for i, l in enumerate(loops):
        enclosing = [
            (j, o) for j, o in enumerate(loops)
            if i != j and l.is_nested_inside(o)
        ]
        if not enclosing:
            parents[i] = None
        else:
            parents[i] = min(enclosing, key=lambda jo: len(jo[1].nodes))[0]

    # Map BB → innermost loop index.
    innermost: dict[BasicBlock, int] = {}
    for bb in prog.blocks.values():
        candidates = [(i, l) for i, l in enumerate(loops) if bb in l.nodes]
        if candidates:
            i_best, _ = min(candidates, key=lambda il: len(il[1].nodes))
            innermost[bb] = i_best

    return LoopForest(loops=loops, parents=parents, innermost=innermost)


def _build_cfg_graph(prog: SSAProgram) -> nx.DiGraph:
    g = nx.DiGraph()
    for bb in prog.blocks.values():
        g.add_node(bb)
    for bb in prog.blocks.values():
        for s in bb.successors:
            g.add_edge(bb, s)
    return g


def _bb_sort_key(bb: BasicBlock) -> tuple:
    """Stable cross-run sort key for a basic block: (file, first-line).
    Falls back to id() for BBs with no assignments (defensive)."""
    if bb.assignments:
        loc = bb.assignments[0].location
        return (loc.file, loc.line)
    return ("", 0, id(bb))


def _select_back_edges(
    full_graph: nx.DiGraph,
    scc: set[BasicBlock],
    entries: set[BasicBlock],
) -> tuple[set[tuple[BasicBlock, BasicBlock]], set[tuple[BasicBlock, BasicBlock]]]:
    """Pick a set of edges to designate as back-edges such that the
    remaining within-SCC edges form a DAG.

    Strategy: DFS from each entry through SCC-internal edges, marking
    edges that close a cycle (target on the DFS stack) as back-edges.
    Iteration order uses :func:`_bb_sort_key` (file + first-line) so
    results are stable across runs.
    """
    sub = full_graph.subgraph(scc).copy()
    back: set[tuple[BasicBlock, BasicBlock]] = set()

    # Tarjan-style DFS marking back-edges.
    color: dict[BasicBlock, str] = {n: "white" for n in scc}

    def dfs(u: BasicBlock) -> None:
        color[u] = "gray"
        for v in sorted(sub.successors(u), key=_bb_sort_key):
            c = color[v]
            if c == "gray":
                back.add((u, v))
            elif c == "white":
                dfs(v)
        color[u] = "black"

    for entry in sorted(entries, key=_bb_sort_key):
        if color[entry] == "white":
            dfs(entry)
    # Any SCC nodes not reached from entries (e.g. multi-entry
    # irreducible structure) — start fresh DFS to ensure coverage.
    for n in sorted(scc, key=_bb_sort_key):
        if color[n] == "white":
            dfs(n)

    body_dag: set[tuple[BasicBlock, BasicBlock]] = {
        (u, v) for u, v in sub.edges if (u, v) not in back
    }
    return back, body_dag
