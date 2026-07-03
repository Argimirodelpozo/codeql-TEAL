"""Iterative dominator-set computation — one source of truth.

The standard worklist fixpoint ``dom(entry) = {entry}``;
``dom(n) = {n} ∪ ⋂_p dom(p)`` was hand-rolled four times over four node types
(``CFG`` BasicBlocks, ``SuperCFG`` SuperBlocks, ``detections.common`` BBs with a
file filter, and the lifted-IR block ids in ``lift.fund_flow``). This
generic version is parameterised by accessor callables so all four call it.

Pure — no ``tealtools`` imports — so every layer can use it without a cycle.
"""
from __future__ import annotations

from typing import Callable, Hashable, Iterable, TypeVar

N = TypeVar("N", bound=Hashable)


def iterative_dominators(
    nodes: Iterable[N],
    entries: Iterable[N],
    preds_of: Callable[[N], Iterable[N]],
) -> dict[N, set[N]]:
    """Dominator sets over a directed graph, including each node itself.

    ``nodes``: every node in the graph. ``entries``: the entry nodes (each
    dominated only by itself). ``preds_of(n)``: ``n``'s predecessors. Reflexive:
    ``n in dom[n]``. A non-entry node with no predecessors is unreachable and is
    left saturated (dominated by everything), the conventional treatment.

    Standard monotone fixpoint: ``dom(entry) = {entry}``;
    ``dom(n) = {n} ∪ ⋂_{p ∈ preds(n)} dom(p)``.
    """
    nodes = list(nodes)
    all_nodes = set(nodes)
    entry_set = set(entries)
    dom: dict[N, set[N]] = {
        n: ({n} if n in entry_set else set(all_nodes)) for n in nodes
    }
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n in entry_set:
                continue
            preds = list(preds_of(n))
            if not preds:
                continue  # unreachable; leave saturated
            new = {n} | set.intersection(*(dom[p] for p in preds))
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom
