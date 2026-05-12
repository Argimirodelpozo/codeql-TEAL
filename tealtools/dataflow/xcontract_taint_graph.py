"""Cross-contract taint graph: a unified flow graph spanning a
caller plus its known callees, with bridge edges modelling the
appcall boundary.

For each ``itxn_submit`` whose ``ApplicationID`` resolves in the
provided registry, the corresponding callee's :class:`TaintGraph`
is built and merged into one big :class:`networkx.DiGraph` with
nodes qualified by AppID. Bridge edges connect:

- **Forward** — caller's ``itxn_field ApplicationArgs`` (per index
  ``i``) → every ``txna ApplicationArgs i`` read in the callee.
  Edge kind: ``"appcall-arg"``.
- **Forward (Sender)** — implicitly: callee's ``txn Sender`` reads
  resolve to the caller's app addr. Modelled as a sentinel source
  node ``("caller-app-addr", caller_app_id)`` with edges to every
  ``txn Sender`` in the callee. (TODO; not yet implemented.)
- **Backward** — callee's ``log`` ops on approving paths →
  caller's ``itxn``/``itxnas`` reads of ``ApplicationLogs`` after
  the submit. Edge kind: ``"appcall-return"``. (TODO.)

Slice 1 implements forward arg-flow bridges only — that's enough
to demonstrate cross-contract reachability for the typical
"attacker arg → callee state mutation" detector.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

import networkx as nx

from ..ssa import SSAProgram
from ..xcontract import AppcallSite, find_appcall_sites, load_registry
from .taint_graph import Node, TaintGraph


@dataclass(frozen=True)
class XContractNode:
    """A node in a cross-contract graph. ``app_id=None`` means the
    caller; an ``int`` means a callee identified by its AppID."""

    app_id: Optional[int]
    inner: Node

    def __repr__(self) -> str:
        scope = "caller" if self.app_id is None else f"app{self.app_id}"
        return f"{scope}:{self.inner!r}"


@dataclass
class XContractTaintGraph:
    """Cross-contract taint graph stitched from per-DB ``TaintGraph``
    instances plus appcall bridge edges."""

    g: nx.DiGraph
    caller: TaintGraph
    callees: dict[int, TaintGraph]
    sites: list[AppcallSite]

    @classmethod
    def build(
        cls,
        caller_prog: SSAProgram,
        registry: dict[int, str] | str | Path,
    ) -> "XContractTaintGraph":
        """Build the unified graph. ``registry`` may be a pre-loaded
        ``{app_id: db_path}`` dict, or a yaml path that
        :func:`tealtools.xcontract.load_registry` accepts."""
        if not isinstance(registry, dict):
            registry = load_registry(registry)
        caller_tg = TaintGraph.of(caller_prog)
        sites = find_appcall_sites(caller_prog, registry)
        callees: dict[int, TaintGraph] = {}
        for site in sites:
            if site.app_id in callees:
                continue
            callee_prog = SSAProgram(str(site.callee_db))
            callees[site.app_id] = TaintGraph.of(callee_prog)
        big = cls._merge(caller_tg, callees, sites)
        return cls(g=big, caller=caller_tg, callees=callees, sites=sites)

    # --- construction --------------------------------------------------

    @staticmethod
    def _wrap(app_id: Optional[int], n: Node) -> XContractNode:
        return XContractNode(app_id=app_id, inner=n)

    @staticmethod
    def _merge(
        caller_tg: TaintGraph,
        callees: dict[int, TaintGraph],
        sites: list[AppcallSite],
    ) -> nx.DiGraph:
        big: nx.DiGraph = nx.DiGraph()
        # Caller nodes + edges
        _copy_into(big, caller_tg, app_id=None)
        # Callee nodes + edges, qualified by AppID
        for app_id, tg in callees.items():
            _copy_into(big, tg, app_id=app_id)
        # Bridge edges per appcall site
        for site in sites:
            if site.app_id not in callees:
                continue
            _add_arg_bridges(big, caller_tg, callees[site.app_id], site)
        return big

    # --- queries (mirror TaintGraph) ----------------------------------

    def nodes(self) -> Iterable[XContractNode]:
        return self.g.nodes  # type: ignore[return-value]

    def find(
        self,
        *,
        app_id: Optional[int] = "any",  # type: ignore[assignment]
        op: Optional[str] = None,
        immediates: Optional[str] = None,
        ql_class: Optional[str] = None,
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> list[XContractNode]:
        """Find nodes across the unified graph. ``app_id="any"``
        (default) matches every scope; ``app_id=None`` matches only
        the caller; an int matches that specific callee."""
        out: list[XContractNode] = []
        for xn in self.g.nodes:
            if app_id != "any" and xn.app_id != app_id:
                continue
            attrs = self.g.nodes[xn]
            n = xn.inner
            if op is not None and attrs.get("op") != op:
                continue
            if immediates is not None and attrs.get("immediates") != immediates:
                continue
            if ql_class is not None and n.ql_class != ql_class:
                continue
            if file is not None and n.file != file:
                continue
            if line is not None and n.line != line:
                continue
            out.append(xn)
        return out

    def reachable_from(self, src: XContractNode) -> set[XContractNode]:
        if src not in self.g:
            return set()
        return set(nx.descendants(self.g, src)) | {src}

    def reachable_from_any(self, srcs: Iterable[XContractNode]) -> set[XContractNode]:
        out: set[XContractNode] = set()
        for s in srcs:
            if s in self.g:
                out |= self.reachable_from(s)
        return out

    def paths_between(
        self,
        srcs: Iterable[XContractNode],
        dsts: Iterable[XContractNode],
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[XContractNode]]:
        srcs_list = [s for s in srcs if s in self.g]
        dsts_set = {d for d in dsts if d in self.g}
        out: list[list[XContractNode]] = []
        for s in srcs_list:
            for d in dsts_set:
                for path in nx.all_simple_paths(
                    self.g, s, d,
                    cutoff=max_length,
                ):
                    out.append(list(path))
                    if len(out) >= max_paths:
                        out.sort(key=len)
                        return out
        out.sort(key=len)
        return out

    def op_of(self, xn: XContractNode) -> Optional[str]:
        if xn not in self.g:
            return None
        return self.g.nodes[xn].get("op")

    def immediates_of(self, xn: XContractNode) -> Optional[str]:
        if xn not in self.g:
            return None
        return self.g.nodes[xn].get("immediates")


# --- copying ------------------------------------------------------


def _copy_into(big: nx.DiGraph, tg: TaintGraph, *, app_id: Optional[int]) -> None:
    for n, attrs in tg.g.nodes(data=True):
        big.add_node(XContractNode(app_id=app_id, inner=n), **attrs)
    for u, v, data in tg.g.edges(data=True):
        # Copy with a shallow new kinds set so prunes on big don't
        # mutate the per-DB tg.
        big.add_edge(
            XContractNode(app_id=app_id, inner=u),
            XContractNode(app_id=app_id, inner=v),
            kinds=set(data.get("kinds", ())),
        )


# --- appcall bridges ----------------------------------------------


def _add_arg_bridges(
    big: nx.DiGraph,
    caller_tg: TaintGraph,
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """For each ``itxn_field ApplicationArgs`` at the caller's site,
    bridge to every ``txna ApplicationArgs i`` read in the callee."""
    for index, caller_node in _caller_arg_field_nodes(caller_tg, site):
        callee_reads = callee_tg.find(op="txna", immediates=f"ApplicationArgs {index}")
        for cn in callee_reads:
            big.add_edge(
                XContractNode(app_id=None, inner=caller_node),
                XContractNode(app_id=site.app_id, inner=cn),
                kinds={"appcall-arg"},
            )


def _caller_arg_field_nodes(
    caller_tg: TaintGraph,
    site: AppcallSite,
) -> Iterator[tuple[int, Node]]:
    """Yield ``(arg_index, node)`` for each ``itxn_field ApplicationArgs``
    op contributing to ``site``'s submit. The arg index is the
    push-order position within this submit's itxn block."""
    # Walk the caller's assignments in source order, finding the
    # itxn block this submit belongs to and counting ApplicationArgs
    # field-set ops as we go.
    prog = caller_tg.prog
    in_block = False
    arg_index = 0
    for a in prog.assignments:
        if a.location.file != site.file:
            continue
        if a.op in ("itxn_begin", "itxn_next"):
            in_block = True
            arg_index = 0
            continue
        if not in_block:
            continue
        if a.op == "itxn_submit" and a.location.line == site.submit_line:
            return  # done with this submit
        if a.op == "itxn_field" and a.immediates.strip() == "ApplicationArgs":
            # Find the matching graph node by (file, line)
            for n in caller_tg.nodes():
                if n.file == site.file and n.line == a.location.line:
                    yield arg_index, n
                    break
            arg_index += 1
