"""SCC-based loop detection: every cyclic region of a :class:`SSAProgram`'s CFG,
the nesting tree over them, and each loop's back-edges / body DAG.

SCCs rather than natural loops (back-edge + dominator), because compiler-emitted
TEAL is regularly irreducible — multi-entry cycles a dominator-based finder
misses entirely, leaving a real loop summarised as straight-line code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

import networkx as nx

from .ssa import BasicBlock, SSAProgram


@dataclass
class Loop:
    """One cycle region (a non-trivial SCC)."""

    nodes: set[BasicBlock]
    entries: set[BasicBlock]                            # reached from OUTSIDE the SCC
    back_edges: set[tuple[BasicBlock, BasicBlock]]      # cut these -> acyclic
    body_dag_edges: set[tuple[BasicBlock, BasicBlock]]  # the remaining in-SCC edges

    def exits(self) -> set[BasicBlock]:
        """BBs outside the loop that a body BB branches to."""
        out: set[BasicBlock] = set()
        for bb in self.nodes:
            for s in bb.successors:
                if s not in self.nodes:
                    out.add(s)
        return out

    def is_nested_inside(self, other: "Loop") -> bool:
        """True when this loop's nodes are a strict subset of ``other``'s."""
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
        """Loops innermost-first — nesting leaves before their ancestors,
        construction order within a level."""
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
    """Build a :class:`LoopForest` for ``prog``'s CFG (SCC + greedy back-edge
    selection; no dominators, so irreducible regions work).

    ``graph`` swaps in another CFG view — a BB→BB :class:`nx.DiGraph` over
    ``prog.blocks``, e.g. with ``callsub``/``retsub`` edges cut so cross-sub
    recursion isn't misread as a loop."""
    g = graph if graph is not None else _build_cfg_graph(prog)
    loops: list[Loop] = []
    parents: dict[int, Optional[int]] = {}

    def _collect(sub: nx.DiGraph, parent: Optional[int]) -> None:
        """Find the loops in ``sub``, then recurse into each one's body.

        HAZARD: SCCs are a PARTITION, so one pass can never see a nested loop
        (``for i: for j:`` returns as one SCC) and the inner repetition goes
        invisible — a nested body then folds as one pass per outer iteration,
        an UNDER-count. Cutting this loop's back edges leaves any genuinely
        nested loop as a surviving SCC."""
        for scc_nodes in nx.strongly_connected_components(sub):
            if len(scc_nodes) == 1:
                (only,) = scc_nodes
                # Trivial unless self-loop.
                if not sub.has_edge(only, only):
                    continue
            scc = set(scc_nodes)
            # Entries are relative to THIS subgraph: a nested loop is entered
            # from the enclosing body, not from outside the whole routine.
            entries = {n for n in scc
                       if any(p not in scc for p in sub.predecessors(n))}
            if not entries:
                # Unreachable cycle, or the subgraph IS the cycle. Pick
                # deterministically so back-edge selection has a start.
                entries = {min(scc, key=_bb_sort_key)}
            back_edges, body_dag = _select_back_edges(sub, scc, entries)
            idx = len(loops)
            loops.append(Loop(
                nodes=scc,
                entries=entries,
                back_edges=back_edges,
                body_dag_edges=body_dag,
            ))
            parents[idx] = parent
            if not back_edges:
                continue                  # nothing removed -> no further nesting
            # Cut ONLY the edges closing THIS loop (those returning to a
            # header): ``_select_back_edges`` reports an inner loop's back edges
            # too, and cutting those would break the nested cycle and hide it.
            # Full-set fallback keeps termination when no edge targets a header.
            header_edges = [(u, v) for (u, v) in back_edges if v in entries]
            inner = sub.subgraph(scc).copy()
            inner.remove_edges_from(header_edges or back_edges)
            _collect(inner, idx)

    _collect(g, None)

    # Map BB → innermost (smallest) containing loop index.
    innermost: dict[BasicBlock, int] = {}
    for bb in prog.blocks.values():
        candidates = [(i, l) for i, l in enumerate(loops) if bb in l.nodes]
        if candidates:
            i_best, _ = min(candidates, key=lambda il: (len(il[1].nodes), il[0]))
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
    """Stable cross-run sort key ``(file, first-line)``, ``id()`` for an empty
    BB (defensive)."""
    if bb.assignments:
        loc = bb.assignments[0].location
        return (loc.file, loc.line)
    return ("", 0, id(bb))


def _select_back_edges(
    full_graph: nx.DiGraph,
    scc: set[BasicBlock],
    entries: set[BasicBlock],
) -> tuple[set[tuple[BasicBlock, BasicBlock]], set[tuple[BasicBlock, BasicBlock]]]:
    """Designate back-edges — DFS from each entry, marking any edge whose target
    is already on the stack — so the remaining within-SCC edges form a DAG;
    :func:`_bb_sort_key` ordering keeps the choice stable across runs."""
    sub = full_graph.subgraph(scc).copy()
    back: set[tuple[BasicBlock, BasicBlock]] = set()

    # white = unvisited, gray = ON the DFS stack (an edge into gray closes a
    # cycle, i.e. is a back-edge), black = finished.
    color: dict[BasicBlock, str] = {n: "white" for n in scc}

    def dfs(root: BasicBlock) -> None:
        """Iterative DFS — an explicit stack, since ~1000-block programs blow
        Python's recursion limit."""
        # Each frame is [node, iterator over its sorted successors].
        color[root] = "gray"
        stack: list = [[root, iter(sorted(sub.successors(root), key=_bb_sort_key))]]
        while stack:
            u, it = stack[-1]
            advanced = False
            for v in it:
                c = color[v]
                if c == "gray":
                    back.add((u, v))
                elif c == "white":
                    color[v] = "gray"
                    stack.append(
                        [v, iter(sorted(sub.successors(v), key=_bb_sort_key))]
                    )
                    advanced = True
                    break
            if not advanced:
                color[u] = "black"
                stack.pop()

    for entry in sorted(entries, key=_bb_sort_key):
        if color[entry] == "white":
            dfs(entry)
    # Multi-entry irreducible structure: cover nodes no entry reached.
    for n in sorted(scc, key=_bb_sort_key):
        if color[n] == "white":
            dfs(n)

    body_dag: set[tuple[BasicBlock, BasicBlock]] = {
        (u, v) for u, v in sub.edges if (u, v) not in back
    }
    return back, body_dag
