"""Shared read-queries over a ``self.g: networkx.DiGraph`` — the node-attribute
getters and reachability helpers that ``TaintGraph`` / ``GroupTaintGraph`` /
``XContractTaintGraph`` each re-implemented identically. Divergent methods
(``paths`` / ``paths_between``, whose signatures differ per view; the per-view
``find`` / ``build``) stay on the concrete classes. Consolidated in the spirit of
``ssa/operands.py`` and ``cfg/dominance.py``.
"""
from __future__ import annotations

from typing import Iterable, Optional

import networkx as nx


class NxGraphView:
    """Mixin: read-queries over ``self.g`` (a ``networkx.DiGraph`` the concrete
    dataclass supplies). Node attributes ``op`` / ``immediates`` are read off
    ``g.nodes[node]``; missing nodes return the empty/None answer rather than
    raising."""

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
