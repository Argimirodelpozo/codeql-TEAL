"""Shared call-matched loop regions, independent of numeric and cost proofs."""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .cfg import CFG
from .dominance import iterative_dominators
from .subroutines import identify_subroutines
from ..ssa import BasicBlock, SSAProgram
from ..ssa.operands import terminator_op as _terminator


@dataclass(frozen=True)
class _LoopShape:
    kind: str
    header: BasicBlock
    entries: tuple[BasicBlock, ...]
    body: frozenset[BasicBlock]
    back_edges: tuple[tuple[BasicBlock, BasicBlock], ...]


def _reachable(cfg: CFG, pp=None) -> set[BasicBlock]:
    out: set[BasicBlock] = set()
    for entry in cfg.entries:
        if entry in out:
            continue
        out.add(entry)
        work = [entry]
        while work:
            block = work.pop()
            for successor in block.successors:
                if pp is not None and not pp.edge_is_feasible(block, successor):
                    continue
                if successor not in out:
                    out.add(successor)
                    work.append(successor)
    return out


def _routine_graph(
    prog: SSAProgram, cfg: CFG, pp=None,
) -> tuple[nx.DiGraph, tuple[BasicBlock, ...]]:
    """Call-summary graph used for loop structure.

    A call block flows to its matched continuation and each subroutine entry is
    an additional graph root.  A ``retsub`` has no outgoing edge in this view.
    This prevents one callee's return from being paired with another caller's
    continuation while still exposing loops in caller and callee routines.
    Callee execution cost is handled conservatively as a degradation on a
    cycle containing ``callsub`` rather than splicing context-insensitive
    return edges into the loop graph.
    """
    if pp is None:
        from ..cfg.path_predicates import PathPredicateAnalysis
        pp = PathPredicateAnalysis(prog)
    reached = _reachable(cfg, pp)
    subs = identify_subroutines(prog)
    roots = tuple(dict.fromkeys([
        *(b for b in cfg.entries if b in reached),
        *(b for b in subs["entries"] if b in reached),
    ]))
    graph = nx.DiGraph()
    graph.add_nodes_from(reached)
    continuations = subs["continuations"]
    for bb in reached:
        term = _terminator(bb)
        if term == "callsub":
            cont = continuations.get(bb)
            if cont in reached:
                graph.add_edge(bb, cont)
            continue
        if term in {"retsub", "return", "err"}:
            continue
        for successor in bb.successors:
            if successor in reached and pp.edge_is_feasible(bb, successor):
                graph.add_edge(bb, successor)
    return graph, roots


def _dominators(graph: nx.DiGraph, roots: tuple[BasicBlock, ...]) -> dict:
    nodes = list(graph.nodes)
    return iterative_dominators(nodes, roots, lambda b: graph.predecessors(b))


def _natural_loops(graph: nx.DiGraph, roots: tuple[BasicBlock, ...]) -> list[_LoopShape]:
    dom = _dominators(graph, roots)
    by_header: dict[BasicBlock, list[tuple[BasicBlock, BasicBlock]]] = {}
    for source, target in graph.edges:
        if target in dom.get(source, ()):
            by_header.setdefault(target, []).append((source, target))

    out: list[_LoopShape] = []
    for header, edges in by_header.items():
        body = {header}
        work = [source for source, _ in edges]
        while work:
            node = work.pop()
            if node in body:
                continue
            body.add(node)
            work.extend(p for p in graph.predecessors(node) if p not in body)
        out.append(_LoopShape(
            "reducible", header, (header,), frozenset(body), tuple(edges)
        ))
    return out


def _cyclic_sccs(graph: nx.DiGraph) -> list[frozenset[BasicBlock]]:
    out: list[frozenset[BasicBlock]] = []
    for raw in nx.strongly_connected_components(graph):
        comp = frozenset(raw)
        if len(comp) > 1 or any(graph.has_edge(b, b) for b in comp):
            out.append(comp)
    return out


def _loop_shapes(graph: nx.DiGraph, roots: tuple[BasicBlock, ...]) -> list[_LoopShape]:
    natural = _natural_loops(graph, roots)
    out = list(natural)
    for comp in _cyclic_sccs(graph):
        entry_nodes = {
            node for node in comp
            if any(pred not in comp for pred in graph.predecessors(node))
            or node in roots
        }
        # A maximal SCC with several entries is irreducible even if it also
        # contains one or more nested natural loops.
        if len(entry_nodes) <= 1:
            continue
        ordered = tuple(sorted(entry_nodes, key=lambda b: (b.file, b.first_line)))
        internal_edges = tuple((u, v) for u, v in graph.edges if u in comp and v in comp)
        out.append(_LoopShape(
            "irreducible", ordered[0], ordered, comp, internal_edges
        ))
    return out
