"""Cross-contract taint graph — a caller plus its known callees, merged with
AppID-qualified nodes and bridge edges over the appcall boundary.

Four bridges: forwarded ``ApplicationArgs`` (``appcall-arg``), forwarded foreign
arrays (``appcall-foreign``), the callee's ``txn Sender`` (``appcall-sender``),
and the callee's ``log`` back into the caller's inner-txn log reads
(``appcall-return``).

HAZARD: inside a callee, ``txn Sender`` is the CALLER APP's address, not the end
user's — a callee that authorises on ``Sender`` is trusting whichever app called
it. That is why the sender bridge exists at all."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

import networkx as nx

from ._nx_view import NxGraphView, copy_into, sensitive_sinks

from ..ssa import SSAProgram
from ..intercontract.analysis import AppcallSite, find_appcall_sites, load_registry
from .taint_graph import Node, TaintGraph


@dataclass(frozen=True)
class XContractNode:
    """A graph node; ``app_id=None`` is the caller, an int is that callee."""

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
        """Build the graph TRANSITIVELY (A->B->C->…), bridging at every hop."""
        from collections import deque

        if not isinstance(registry, dict):
            registry = load_registry(registry)
        caller_tg = TaintGraph.of(caller_prog)
        root_sites = find_appcall_sites(caller_prog, registry)
        callees: dict[int, TaintGraph] = {}
        tg_by_id: dict = {None: caller_tg}     # calling app id (None = root) -> graph
        edges: list = []                       # (caller_app_id, site) per appcall
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
        for app_id, tg in tg_by_id.items():
            _copy_into(big, tg, app_id=app_id)
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
        """Find nodes; ``app_id="any"`` spans every scope, ``None`` is the caller only."""
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


# HAZARD: the caller's i-th pushed entry is read by the callee at ``i + offset``,
# because some arrays reserve slot 0 for an AVM implicit value. Dropping the
# offset bridges every foreign-array flow to the WRONG index.
#   ApplicationArgs — no implicit entry            (callee read i   <- push i)
#   Accounts        — callee read 0 == Sender      (callee read i+1 <- push i)
#   Applications    — callee read 0 == current app (callee read i+1 <- push i)
#   Assets          — no implicit entry            (callee read i   <- push i)
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
    """Forward each array the caller sets on the inner txn to the matching
    positional read in the callee, applying the implicit-entry offset.

    A dynamic ``txnas`` read may select any position, so every pushed element
    conservatively reaches it. Its index operand already has a normal def-use
    edge into the read node and therefore remains a separate dependency.
    """
    for field, offset in _FORWARD_ARRAYS.items():
        kind = "appcall-arg" if field == "ApplicationArgs" else "appcall-foreign"
        dynamic_reads = _callee_dynamic_array_reads(callee_tg, field)
        for push_i, caller_node in _caller_field_nodes(caller_tg, site, field):
            for cn in (*_callee_array_reads(callee_tg, field, push_i + offset),
                       *dynamic_reads):
                big.add_edge(
                    XContractNode(app_id=caller_app_id, inner=caller_node),
                    XContractNode(app_id=site.app_id, inner=cn),
                    kinds={kind},
                )


def _callee_array_reads(callee_tg: TaintGraph, field: str, index: int) -> list[Node]:
    """Callee nodes reading ``field`` at literal ``index``."""
    imm = f"{field} {index}"
    return (callee_tg.find(op="txna", immediates=imm)
            + callee_tg.find(op="txn", immediates=imm))


def _callee_dynamic_array_reads(callee_tg: TaintGraph, field: str) -> list[Node]:
    """Callee reads whose array index is popped from the stack."""
    return callee_tg.find(op="txnas", immediates=field)


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
    """Connect a per-caller sentinel to every ``txn Sender`` read in the callee,
    since those resolve to the CALLER's app address."""
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
    """Bridge every callee ``log`` to the caller's post-submit reads of the inner
    txn's ``Logs`` array or its scalar ``LastLog``.

    Both forms must be covered: a verdict that flips depending on which
    equivalent return opcode the contract used is a false verdict."""
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
    """Yield ``(push_index, node)`` per ``itxn_field <field>`` feeding ``site``'s
    submit, the index being that field-set's position within the inner txn.

    HAZARD: fields are buffered and only yielded once the group's submit matches
    ``site.submit_line``, or an EARLIER submit's fields leak into a later site."""
    from ..ssa.operands import const_int

    prog = caller_tg.prog
    in_block = False
    push_index = 0
    # Buffered PER INNER TXN, not per group: `itxn_next` starts a new txn that
    # reuses push indices from 0, so one flat buffer would merge two txns'
    # fields under colliding indices onto this site's single callee.
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
                # Prefer the txn actually targeting this callee, else fall back
                # to every txn in the group — over-approximating, so extra edges
                # inflate reachability rather than dropping a real flow.
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
                for n in caller_tg.nodes():
                    if n.file == site.file and n.line == a.location.line:
                        txns[-1].append((push_index, n))
                        break
                push_index += 1


# --- cross-contract taint reachability detector -------------------


@dataclass(frozen=True)
class CrossTaintFinding:
    """A caller input reaching a sensitive sink across the appcall boundary."""

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
    """A witness path through a callee scope, or ``None`` if every ``src -> sink``
    path stays in the caller.

    A callee node lies on some such path iff it is both forward-reachable from
    ``src`` and backward-reachable to ``sink``; one existing means the value
    crossed the boundary and returned, which the caller analysis cannot see."""
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
    """Caller inputs reaching a sensitive sink ACROSS the appcall boundary, in
    both directions — forward into a callee, or back via the return channel.

    A caller-scope sink reachable WITHOUT crossing the boundary belongs to the
    single-program detectors and is deliberately not reported here."""
    sources = [
        xn for xn in (xtg.find(app_id=None, op="txna")
                      + xtg.find(app_id=None, op="txn"))
        if (xtg.immediates_of(xn) or "").startswith("ApplicationArgs")
    ]
    # Caller-scope unknown-scratch loads are attacker-MAY sources too: the
    # value the SSA could not name may be anything an attacker stored, so a
    # boundary crossing from one is as reportable as one from an arg read.
    # Callee-scope unknowns are deliberately NOT seeded — a callee-internal
    # flow never crosses the boundary, which this reporter is scoped to.
    sources += [
        xn for xn in xtg.nodes()
        if xn.app_id is None and xtg.caller.is_unknown_scratch(xn.inner)
    ]
    sinks = _sensitive_sinks(xtg)
    findings: list[CrossTaintFinding] = []
    for src in sources:
        reach = xtg.reachable_from(src)
        for sink_xn, name in sinks:
            if sink_xn not in reach:
                continue  # unreachable
            if sink_xn.app_id is None:
                # Caller-scope sink: only the return channel counts here.
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
