"""Cross-contract taint graph: a unified flow graph spanning a
caller plus its known callees, with bridge edges modelling the
appcall boundary.

For each ``itxn_submit`` whose ``ApplicationID`` resolves in the
provided registry, the corresponding callee's :class:`TaintGraph`
is built and merged into one big :class:`networkx.DiGraph` with
nodes qualified by AppID. Bridge edges connect:

- **Forward (args)** — caller's ``itxn_field ApplicationArgs`` (per
  index ``i``) → every ``txna ApplicationArgs i`` read in the callee.
  Edge kind: ``"appcall-arg"``.
- **Forward (Sender)** — the callee's ``txn Sender`` reads resolve to
  the caller's app address. Modelled as a single sentinel source node
  (:data:`_CALLER_APP_ADDR`, scope ``None``) with edges to every
  ``txn Sender`` read in the callee. Edge kind: ``"appcall-sender"``.
- **Backward (return)** — the callee's ``log`` ops → the caller's
  ``itxn``/``itxna``/``itxnas`` reads of the ``Logs`` field after the
  submit. Edge kind: ``"appcall-return"``. ``log`` has no SSA output
  but is still a graph node (the QL def-use step puts an edge into it
  from the logged value's producer), so it can serve as the bridge
  source directly.

Together these let :func:`cross_taint_findings` follow an attacker
input from the caller, across the appcall boundary, to a sensitive
sink in the callee (or back to the caller via the return channel).
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
            callee_tg = callees[site.app_id]
            _add_arg_bridges(big, caller_tg, callee_tg, site)
            _add_sender_bridge(big, caller_tg, callee_tg, site)
            _add_return_bridges(big, caller_tg, callee_tg, site)
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


# Sentinel source standing in for "the caller's application address",
# which is the Sender of every inner transaction the caller submits.
_CALLER_APP_ADDR = Node(file="<caller-app-addr>", line=0, ql_class="CallerAppAddr")


def _add_sender_bridge(
    big: nx.DiGraph,
    caller_tg: TaintGraph,
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """The callee's ``txn Sender`` reads resolve to the caller's app
    address (the inner-txn sender). Seed a single sentinel source node
    and connect it to every ``txn Sender`` read in the callee, so a
    callee that trusts ``Sender`` is reachable from caller context."""
    sender_reads = callee_tg.find(op="txn", immediates="Sender")
    if not sender_reads:
        return
    sentinel = XContractNode(app_id=None, inner=_CALLER_APP_ADDR)
    if sentinel not in big:
        big.add_node(sentinel, op="caller-app-addr", immediates=None, const_values=())
    for cn in sender_reads:
        big.add_edge(
            sentinel,
            XContractNode(app_id=site.app_id, inner=cn),
            kinds={"appcall-sender"},
        )


def _add_return_bridges(
    big: nx.DiGraph,
    caller_tg: TaintGraph,
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """The callee's ``log`` ops feed the caller's reads of the inner
    txn's ``Logs`` field after the submit. Bridge every callee ``log``
    node to every caller ``itxn``/``itxna``/``itxnas Logs`` read that
    sits after this site's submit line."""
    callee_logs = callee_tg.find(op="log")
    if not callee_logs:
        return
    caller_log_reads = [
        n for n in caller_tg.nodes()
        if caller_tg.op_of(n) in ("itxn", "itxna", "itxnas")
        and (caller_tg.immediates_of(n) or "").split()[:1] == ["Logs"]
        and n.file == site.file
        and n.line > site.submit_line
    ]
    if not caller_log_reads:
        return
    for ln in callee_logs:
        for rn in caller_log_reads:
            big.add_edge(
                XContractNode(app_id=site.app_id, inner=ln),
                XContractNode(app_id=None, inner=rn),
                kinds={"appcall-return"},
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


# --- cross-contract taint reachability detector -------------------


# Sinks whose operand governs value movement or control transfer; a
# tainted value reaching one of these is the thing worth reporting.
_SENSITIVE_ITXN_FIELDS = frozenset({
    "Receiver", "Amount", "AssetReceiver", "AssetAmount",
    "ApplicationID", "RekeyTo", "CloseRemainderTo", "AssetCloseTo",
    "ApprovalProgram", "ClearStateProgram",
})
_STATE_WRITE_OPS = frozenset({"app_global_put", "app_local_put"})


@dataclass(frozen=True)
class CrossTaintFinding:
    """An attacker-controlled caller input that reaches a sensitive
    sink in a callee, across the appcall boundary."""

    source: XContractNode
    sink: XContractNode
    sink_name: str
    path: tuple  # tuple[XContractNode, ...] — a shortest witness path

    def pretty(self) -> str:
        via = " -> ".join(repr(n) for n in self.path)
        return f"{self.source!r}  =>  {self.sink_name}@{self.sink!r}   [{via}]"

    def to_dict(self) -> dict:
        return {
            "source": repr(self.source),
            "sink": repr(self.sink),
            "sink_name": self.sink_name,
            "path": [repr(n) for n in self.path],
        }


def _sensitive_sinks(xtg: "XContractTaintGraph") -> list[tuple[XContractNode, str]]:
    out: list[tuple[XContractNode, str]] = []
    for xn in xtg.nodes():
        op = xtg.op_of(xn)
        imm = xtg.immediates_of(xn)
        if op == "itxn_field" and imm in _SENSITIVE_ITXN_FIELDS:
            out.append((xn, f"itxn_field {imm}"))
        elif op in _STATE_WRITE_OPS:
            out.append((xn, op))
    return out


def cross_taint_findings(xtg: "XContractTaintGraph") -> list[CrossTaintFinding]:
    """Report caller-side attacker inputs (``txna ApplicationArgs``)
    that reach a sensitive sink in a callee, following the appcall
    bridge edges. One finding per (source, callee-sink) reachable pair,
    carrying a shortest witness path.

    Cross-boundary only: a sink in the caller's own scope is the job of
    the single-program :mod:`tealtools.dataflow.box` / ``state`` flows;
    here we report exactly the flows that cross an appcall, which is the
    capability the bridges add."""
    sources = [
        xn for xn in xtg.find(app_id=None, op="txna")
        if (xtg.immediates_of(xn) or "").startswith("ApplicationArgs")
    ]
    sinks = _sensitive_sinks(xtg)
    findings: list[CrossTaintFinding] = []
    for src in sources:
        reach = xtg.reachable_from(src)
        for sink_xn, name in sinks:
            if sink_xn.app_id is None or sink_xn not in reach:
                continue  # caller-scope sink, or unreachable
            paths = xtg.paths_between([src], [sink_xn], max_paths=1)
            path = tuple(paths[0]) if paths else (src, sink_xn)
            findings.append(CrossTaintFinding(
                source=src, sink=sink_xn, sink_name=name, path=path,
            ))
    findings.sort(key=lambda f: (repr(f.source), repr(f.sink)))
    return findings


def render_cross_taint(findings: list[CrossTaintFinding]) -> str:
    if not findings:
        return "(no cross-contract taint findings)"
    return "\n".join(f.pretty() for f in findings)
