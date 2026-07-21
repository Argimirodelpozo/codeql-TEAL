"""Shared read-queries over a ``self.g: networkx.DiGraph`` — the node-attribute
getters and reachability helpers that ``TaintGraph`` / ``GroupTaintGraph`` /
``XContractTaintGraph`` each re-implemented identically, plus the merge
(:func:`copy_into`) and sink-classification (:func:`sensitive_sinks`) helpers
the two composite views duplicated almost verbatim. Divergent methods
(``paths`` / ``paths_between``, whose signatures differ per view; the per-view
``find`` / ``build``) stay on the concrete classes. Consolidated in the spirit of
``ssa/operands.py`` and ``cfg/dominance.py``.
"""
from __future__ import annotations

from typing import Callable, Iterable, Optional

import networkx as nx

from ..avm import SENSITIVE_ITXN_FIELDS, STATE_WRITE_OPS


def copy_into(big: "nx.DiGraph", tg, wrap: Callable) -> None:
    """Copy every node/edge of ``tg`` into ``big``, mapping each node through
    ``wrap`` (the composite view's node wrapper).

    Edge ``kinds`` are copied into a NEW set so pruning ``big`` can't mutate
    the per-contract graph it was built from."""
    for n, attrs in tg.g.nodes(data=True):
        big.add_node(wrap(n), **attrs)
    for u, v, data in tg.g.edges(data=True):
        big.add_edge(wrap(u), wrap(v), kinds=set(data.get("kinds", ())))


def sensitive_sinks(view) -> list[tuple[object, str]]:
    """``(node, label)`` for every node of ``view`` that writes a sensitive
    inner-txn field or persistent state — the sink taxonomy shared by the
    group and cross-contract views. Reads through the ``NxGraphView``
    accessors, so it works for any wrapper node type."""
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
