"""Cross-contract taint graph: a unified flow graph spanning a
caller plus its known callees, with bridge edges modelling the
appcall boundary.

For each ``itxn_submit`` whose ``ApplicationID`` resolves in the
provided registry, the corresponding callee's :class:`TaintGraph`
is built and merged into one big :class:`networkx.DiGraph` with
nodes qualified by AppID. Bridge edges connect:

- **Forward (args)** — caller's ``itxn_field ApplicationArgs`` (per
  index ``i``) → every ``txna ApplicationArgs i`` / ``txn ApplicationArgs i``
  read in the callee. Edge kind: ``"appcall-arg"``.
- **Forward (foreign arrays)** — the caller's ``itxn_field
  {Accounts,Assets,Applications}`` entries → the callee's positional
  ``txn``/``txna`` reads of the same array, offset by the AVM implicit
  entry (callee ``Accounts 0`` is the Sender, ``Applications 0`` is the
  current app — see :data:`_FORWARD_ARRAYS`). Edge kind: ``"appcall-foreign"``.
- **Forward (Sender)** — the callee's ``txn Sender`` reads resolve to
  the caller's app address. Modelled as a single sentinel source node
  (:data:`_CALLER_APP_ADDR`, scope ``None``) with edges to every
  ``txn Sender`` read in the callee. Edge kind: ``"appcall-sender"``.
- **Backward (return)** — the callee's ``log`` ops → the caller's
  ``itxn``/``itxna``/``itxnas`` reads of the ``Logs`` field after the
  submit. Edge kind: ``"appcall-return"``. ``log`` has no SSA output
  but is still a graph node (the def-use step puts an edge into it
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

from ._nx_view import NxGraphView, copy_into, sensitive_sinks

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
class XContractTaintGraph(NxGraphView):
    """Cross-contract taint graph stitched from per-contract ``TaintGraph``
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
        *,
        max_depth: int = 4,
    ) -> "XContractTaintGraph":
        """Build the unified graph TRANSITIVELY (A->B->C->...): a TaintGraph
        per reachable contract, plus appcall bridge edges at every hop, so a
        value flows across the whole chain. ``registry`` may be a pre-loaded
        ``{app_id: teal_path}`` dict, or a yaml path that
        :func:`tealql.tealtools.xcontract.load_registry` accepts."""
        from collections import deque

        if not isinstance(registry, dict):
            registry = load_registry(registry)
        caller_tg = TaintGraph.of(caller_prog)
        root_sites = find_appcall_sites(caller_prog, registry)
        callees: dict[int, TaintGraph] = {}
        # AppID of the calling contract (None == root) -> its TaintGraph.
        tg_by_id: dict = {None: caller_tg}
        # (caller_app_id, site) for every appcall edge in the transitive graph.
        edges: list = []
        # BFS over the call graph; each contract loaded + graphed once.
        frontier: deque = deque([(caller_prog, None, 0)])
        while frontier:
            prog, prog_id, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            sites = (root_sites if prog is caller_prog
                     else find_appcall_sites(prog, registry))
            for site in sites:
                edges.append((prog_id, site))
                if site.app_id in callees:
                    continue            # already graphed (dedup + cycle guard)
                cp = SSAProgram(str(site.callee_source))
                cp.propagate_constants()
                tg = TaintGraph.of(cp)
                callees[site.app_id] = tg
                tg_by_id[site.app_id] = tg
                frontier.append((cp, site.app_id, depth + 1))
        big = cls._merge(tg_by_id, callees, edges)
        return cls(g=big, caller=caller_tg, callees=callees, sites=root_sites)

    # --- construction --------------------------------------------------

    @staticmethod
    def _merge(
        tg_by_id: dict,
        callees: dict[int, TaintGraph],
        edges: list,
    ) -> nx.DiGraph:
        big: nx.DiGraph = nx.DiGraph()
        # Every contract's nodes/edges, qualified by AppID (None = root).
        for app_id, tg in tg_by_id.items():
            _copy_into(big, tg, app_id=app_id)
        # Bridge edges per appcall edge: caller_app_id -> site.app_id (callee).
        for caller_app_id, site in edges:
            callee_tg = callees.get(site.app_id)
            caller_tg = tg_by_id.get(caller_app_id)
            if callee_tg is None or caller_tg is None:
                continue
            _add_array_bridges(big, caller_tg, caller_app_id, callee_tg, site)
            _add_sender_bridge(big, caller_tg, caller_app_id, callee_tg, site)
            _add_return_bridges(big, caller_tg, caller_app_id, callee_tg, site)
        return big

    # --- queries (mirror TaintGraph) ----------------------------------

    def find(
        self,
        *,
        app_id: Optional[int] = "any",  # type: ignore[assignment]
        op: Optional[str] = None,
        immediates: Optional[str] = None,
        node_class: Optional[str] = None,
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
            if node_class is not None and n.node_class != node_class:
                continue
            if file is not None and n.file != file:
                continue
            if line is not None and n.line != line:
                continue
            out.append(xn)
        return out

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


# --- copying ------------------------------------------------------


def _copy_into(big: nx.DiGraph, tg: TaintGraph, *, app_id: Optional[int]) -> None:
    copy_into(big, tg, lambda n: XContractNode(app_id=app_id, inner=n))


# --- appcall bridges ----------------------------------------------


# The array fields an appcall forwards into the callee, mapped to the AVM
# implicit-entry offset: the callee reads each array at an index whose 0 slot
# is reserved for an implicit value on some arrays, so the caller's i-th pushed
# entry is read by the callee at index ``i + offset``.
#   ApplicationArgs — no implicit entry          (callee read i  <- push i)
#   Accounts        — callee read 0 == Sender    (callee read i+1 <- push i)
#   Applications    — callee read 0 == current app (callee read i+1 <- push i)
#   Assets          — no implicit entry          (callee read i  <- push i)
_FORWARD_ARRAYS: dict[str, int] = {
    "ApplicationArgs": 0,
    "Accounts": 1,
    "Applications": 1,
    "Assets": 0,
}


def _add_array_bridges(
    big: nx.DiGraph,
    caller_tg: TaintGraph,
    caller_app_id: Optional[int],
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """Forward every array the caller sets on the inner appcall txn
    (``itxn_field {ApplicationArgs,Accounts,Assets,Applications}``) to the
    matching positional read in the callee, accounting for the AVM
    implicit-entry offset (:data:`_FORWARD_ARRAYS`). The callee read may be
    either ``txna FIELD i`` or the equally-valid ``txn FIELD i`` form (both are
    current-txn array reads — the ``txn`` form was previously missed, the same
    gap fixed for ``seeds_for_callee``). ``caller_app_id`` (``None`` = root)
    scopes the caller-side node; ``ApplicationArgs`` keeps the ``appcall-arg``
    kind, the foreign arrays use ``appcall-foreign``."""
    for field, offset in _FORWARD_ARRAYS.items():
        kind = "appcall-arg" if field == "ApplicationArgs" else "appcall-foreign"
        for push_i, caller_node in _caller_field_nodes(caller_tg, site, field):
            for cn in _callee_array_reads(callee_tg, field, push_i + offset):
                big.add_edge(
                    XContractNode(app_id=caller_app_id, inner=caller_node),
                    XContractNode(app_id=site.app_id, inner=cn),
                    kinds={kind},
                )


def _callee_array_reads(callee_tg: TaintGraph, field: str, index: int) -> list[Node]:
    """Callee nodes reading ``field`` at the literal ``index`` via either the
    ``txna`` or the ``txn`` form. The dynamic-index reads (``txnas`` /
    ``gtxnas``, index popped from the stack) aren't pinned to a position, so
    they're conservatively left unbridged for a follow-up."""
    imm = f"{field} {index}"
    return (callee_tg.find(op="txna", immediates=imm)
            + callee_tg.find(op="txn", immediates=imm))


# Sentinel source standing in for "the caller's application address",
# which is the Sender of every inner transaction the caller submits.
_CALLER_APP_ADDR = Node(file="<caller-app-addr>", line=0, node_class="CallerAppAddr")


def _add_sender_bridge(
    big: nx.DiGraph,
    caller_tg: TaintGraph,
    caller_app_id: Optional[int],
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """The callee's ``txn Sender`` reads resolve to the CALLER's app
    address (the inner-txn sender). Seed a per-caller sentinel source node
    and connect it to every ``txn Sender`` read in the callee, so a callee
    that trusts ``Sender`` is reachable from its caller's context."""
    sender_reads = callee_tg.find(op="txn", immediates="Sender")
    if not sender_reads:
        return
    sentinel = XContractNode(app_id=caller_app_id, inner=_CALLER_APP_ADDR)
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
    caller_app_id: Optional[int],
    callee_tg: TaintGraph,
    site: AppcallSite,
) -> None:
    """The callee's ``log`` ops feed the caller's reads of the inner
    txn's log output after the submit. Bridge every callee ``log`` node
    to every caller read of the inner txn's ``Logs`` array OR its scalar
    ``LastLog`` field (the standard single-return read) that sits after
    this site's submit line (``caller_app_id`` scopes them). ``LastLog``
    parity with the group axis (see ``group_taint_graph._add_log_bridges``)
    — the verdict must not flip on which equivalent return opcode was used."""
    callee_logs = callee_tg.find(op="log")
    if not callee_logs:
        return
    caller_log_reads = [
        n for n in caller_tg.nodes()
        if caller_tg.op_of(n) in ("itxn", "itxna", "itxnas")
        and (caller_tg.immediates_of(n) or "").split()[:1] in (["Logs"], ["LastLog"])
        and n.file == site.file
        and n.line > site.submit_line
    ]
    if not caller_log_reads:
        return
    for ln in callee_logs:
        for rn in caller_log_reads:
            big.add_edge(
                XContractNode(app_id=site.app_id, inner=ln),
                XContractNode(app_id=caller_app_id, inner=rn),
                kinds={"appcall-return"},
            )


def _caller_field_nodes(
    caller_tg: TaintGraph,
    site: AppcallSite,
    field: str,
) -> Iterator[tuple[int, Node]]:
    """Yield ``(push_index, node)`` for each ``itxn_field <field>`` op
    contributing to ``site``'s submit. The push index is the position of
    this field-set within the inner txn (reset at ``itxn_begin``/``itxn_next``,
    so it counts the array of the inner txn this submit finalises)."""
    # Walk the caller's assignments in source order, finding the itxn block
    # this submit belongs to and counting <field> field-set ops as we go. Fields
    # are BUFFERED per group (itxn_begin..itxn_submit) and only yielded once the
    # group's submit matches site.submit_line — otherwise an EARLIER submit's
    # fields (in_block never reset) would leak into a later site's callee.
    from ..ssa.operands import const_int

    prog = caller_tg.prog
    in_block = False
    push_index = 0
    # Fields are buffered PER INNER TXN, not per group: `itxn_next` starts a
    # new txn that reuses push indices from 0. Keeping one flat buffer meant a
    # group with two inner txns each setting <field> merged both txns' fields
    # (with colliding push indices) onto the single callee this site names.
    txns: list[list[tuple[int, Node]]] = [[]]
    txn_app_ids: list[Optional[int]] = [None]
    for a in prog.assignments:
        if a.location.file != site.file:
            continue
        if a.op == "itxn_begin":
            in_block = True
            push_index = 0
            txns = [[]]                # new group — drop any prior group's fields
            txn_app_ids = [None]
            continue
        if a.op == "itxn_next":
            push_index = 0             # a new txn in the SAME group
            txns.append([])
            txn_app_ids.append(None)
            continue
        if not in_block:
            continue
        if a.op == "itxn_submit":
            if a.location.line == site.submit_line:
                # Prefer the txn that actually targets this site's callee; if
                # no txn's ApplicationID resolves to it, fall back to every
                # txn in the group (over-approximate: extra edges inflate
                # reachability, never drop it).
                matched = [t for t, aid in zip(txns, txn_app_ids)
                           if aid is not None and aid == site.app_id]
                for bucket in (matched or txns):
                    yield from bucket
                return
            in_block = False           # a different submit — that group wasn't ours
            txns = [[]]
            txn_app_ids = [None]
            continue
        if a.op == "itxn_field":
            imm = a.immediates.strip()
            if imm == "ApplicationID" and a.inputs:
                txn_app_ids[-1] = const_int(a.inputs[0])
            if imm == field:
                # Find the matching graph node by (file, line)
                for n in caller_tg.nodes():
                    if n.file == site.file and n.line == a.location.line:
                        txns[-1].append((push_index, n))
                        break
                push_index += 1


# --- cross-contract taint reachability detector -------------------


# The sink taxonomy (sensitive itxn fields + the full box/app state-write
# family) lives in tealql.tealtools.avm and is applied by
# _nx_view.sensitive_sinks, shared with the group view.


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
    return sensitive_sinks(xtg)


def _boundary_crossing_path(
    xtg: "XContractTaintGraph",
    src: XContractNode,
    sink: XContractNode,
    reach: set,
) -> Optional[tuple]:
    """A witness path ``src -> ... -> sink`` that passes through a callee scope
    (a node with ``app_id is not None``), or ``None`` when every ``src -> sink``
    path stays entirely in the caller.

    A callee-scope node lies on some ``src -> sink`` path iff it is both
    forward-reachable from ``src`` (``reach``) and backward-reachable to ``sink``
    (``ancestors``). If one exists, the attacker value crossed the appcall
    boundary and came back — the RETURN channel — which the single-program caller
    analysis cannot see; we stitch ``src -> mid -> sink`` as the witness."""
    back = xtg.reachable_to(sink)
    mids = [n for n in reach & back if n.app_id is not None]
    if not mids:
        return None
    mid = min(mids, key=repr)                 # deterministic witness pick
    left = xtg.paths_between([src], [mid], max_paths=1)
    right = xtg.paths_between([mid], [sink], max_paths=1)
    if not left or not right:
        return None
    return tuple(left[0]) + tuple(right[0][1:])


def cross_taint_findings(xtg: "XContractTaintGraph") -> list[CrossTaintFinding]:
    """Report caller-side attacker inputs (``txna ApplicationArgs``)
    that reach a sensitive sink ACROSS the appcall boundary, following the
    bridge edges. One finding per (source, sink) reachable pair, carrying a
    shortest witness path.

    Cross-boundary only, in both directions:
    - a sink in a CALLEE reached from a caller input (forward channel), and
    - a sink in the CALLER reached via the RETURN channel — a callee ``log``
      that launders attacker input back to the caller's ``itxn LastLog`` /
      ``Logs`` read and into a caller sink. This lands in the caller's scope but
      is genuinely cross-contract: the caller analysis alone can't tell the
      inner-txn return carries attacker data.

    A caller-scope sink reachable WITHOUT crossing the boundary is left to the
    single-program :mod:`tealql.tealtools.dataflow.box` / ``state`` flows and is
    NOT reported here."""
    sources = [
        xn for xn in (xtg.find(app_id=None, op="txna")
                      + xtg.find(app_id=None, op="txn"))
        if (xtg.immediates_of(xn) or "").startswith("ApplicationArgs")
    ]
    sinks = _sensitive_sinks(xtg)
    findings: list[CrossTaintFinding] = []
    for src in sources:
        reach = xtg.reachable_from(src)
        for sink_xn, name in sinks:
            if sink_xn not in reach:
                continue  # unreachable
            if sink_xn.app_id is None:
                # Caller-scope sink: report ONLY when the flow crosses the
                # appcall boundary (the return channel); a pure-caller flow is
                # the single-program analysis's job.
                path = _boundary_crossing_path(xtg, src, sink_xn, reach)
                if path is None:
                    continue
            else:
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
