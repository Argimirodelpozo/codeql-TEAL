"""Read-queries, merging and sink classification shared by every taint-graph view."""
from __future__ import annotations

from typing import Callable, Iterable, Optional

import networkx as nx

from ..language.avm import SENSITIVE_ITXN_FIELDS, STATE_WRITE_OPS


def copy_into(big: "nx.DiGraph", tg, wrap: Callable) -> None:
    """Copy every node/edge of ``tg`` into ``big``, wrapping each node.

    HAZARD: edge ``kinds`` must be copied into a NEW set — sharing it lets a
    prune of the composite silently mutate the per-contract graph it came from."""
    for n, attrs in tg.g.nodes(data=True):
        big.add_node(wrap(n), **attrs)
    for u, v, data in tg.g.edges(data=True):
        big.add_edge(wrap(u), wrap(v), kinds=set(data.get("kinds", ())))


def sensitive_sinks(view) -> list[tuple[object, str]]:
    """``(node, label)`` for every node writing a sensitive itxn field or state."""
    out: list[tuple[object, str]] = []
    for n in view.nodes():
        op = view.op_of(n)
        if op == "itxn_field":
            imm = view.immediates_of(n)
            if imm in SENSITIVE_ITXN_FIELDS:
                out.append((n, f"itxn_field {imm}"))
        elif op in STATE_WRITE_OPS:
            out.append((n, op))
    return out


class NxGraphView:
    """Mixin of read-queries over ``self.g``; a missing node answers empty/None
    rather than raising."""

    g: "nx.DiGraph"   # provided by the concrete dataclass (annotation only)

    def nodes(self) -> Iterable:
        return self.g.nodes

    def op_of(self, node) -> Optional[str]:
        return self.g.nodes[node].get("op") if node in self.g else None

    def immediates_of(self, node) -> Optional[str]:
        return self.g.nodes[node].get("immediates") if node in self.g else None

    def reachable_from(self, src) -> set:
        if src not in self.g:
            return set()
        return set(nx.descendants(self.g, src)) | {src}

    def reachable_to(self, dst) -> set:
        if dst not in self.g:
            return set()
        return set(nx.ancestors(self.g, dst)) | {dst}

    def reaches(self, src, dst) -> bool:
        return src is dst or (src in self.g and dst in self.reachable_from(src))
