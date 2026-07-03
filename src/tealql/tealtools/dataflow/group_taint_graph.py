"""Atomic-group cross-program taint graph (the horizontal sibling axis).

An atomic group is ``[txn0, txn1, ...]`` submitted together; each runs its own
program, and siblings share state via ``gload i N`` — read scratch slot ``N`` of
group txn ``i``. This loads each member's :class:`TaintGraph`, merges them into
one graph qualified by GROUP INDEX, and splices the scratch-sharing bridge:

    ``store N`` in member i   ->   ``gload i N`` in member k      (i < k)

so a value an earlier member stashes in scratch flows into a later member that
``gload``\\ s it — crossing the trust boundary WITHIN one atomic group (the
``gload``-readable-cross-group scratch that DSE must never drop).

Contrast with the inner-transaction graph
(:class:`tealql.tealtools.dataflow.xcontract_taint_graph.XContractTaintGraph`): that is
the *vertical/nested* axis (A ``itxn_submit``s a call to B), with call/return and
``ApplicationArgs``/``log`` bridges. A group has NO call/return — members run in
sequence, connected only by dataflow — and its composition is EXTERNAL (the user
assembles the group), so :meth:`GroupTaintGraph.build` takes an ORDERED list of
member programs (index = group position), not an AppID registry.

Two member-to-member channels are bridged (both enforcing the AVM ``i < k``
rule — a member may only read an EARLIER, already-executed sibling):

- **scratch** — ``store N`` (member i) -> ``gload i N`` / ``gloads N`` (member k).
  ``gload`` pins the sibling index statically; ``gloads`` pops it from the stack
  so we conservatively bridge every earlier member's ``store N``.
- **log** — ``log`` (member i) -> ``gtxn i LastLog`` / ``gtxna i Logs`` (member k):
  a sibling reads what an earlier member logged (the group analog of xcontract's
  appcall-return channel).

Still conservative: ``stores`` / ``gloadss`` (dynamic SLOT) are left unbridged —
the slot isn't a static immediate — a follow-up.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import networkx as nx

from ..ssa import SSAProgram
from ..avm import SENSITIVE_ITXN_FIELDS, STATE_WRITE_OPS
from .taint_graph import Node, TaintGraph


@dataclass(frozen=True)
class GroupNode:
    """A taint node qualified by the group index of the member it lives in."""

    index: int
    inner: Node

    def __repr__(self) -> str:
        return f"g{self.index}:{self.inner!r}"


@dataclass
class GroupTaintGraph:
    """Per-member :class:`TaintGraph`\\ s merged into one graph, plus the
    ``store -> gload`` scratch bridges between siblings."""

    g: nx.DiGraph
    members: list[TaintGraph]

    @classmethod
    def build(cls, member_progs: list[SSAProgram]) -> "GroupTaintGraph":
        """Build the group graph from an ORDERED list of member programs
        (``member_progs[i]`` is group txn ``i``)."""
        members = [TaintGraph.of(p) for p in member_progs]
        big: nx.DiGraph = nx.DiGraph()
        for idx, tg in enumerate(members):
            _copy_into(big, tg, index=idx)
        _add_scratch_bridges(big, members)
        _add_log_bridges(big, members)
        return cls(g=big, members=members)

    # --- queries -------------------------------------------------------

    def nodes(self) -> Iterable[GroupNode]:
        return self.g.nodes  # type: ignore[return-value]

    def op_of(self, gn: GroupNode) -> Optional[str]:
        return self.g.nodes[gn].get("op") if gn in self.g else None

    def immediates_of(self, gn: GroupNode) -> Optional[str]:
        return self.g.nodes[gn].get("immediates") if gn in self.g else None

    def reachable_from(self, src: GroupNode) -> set[GroupNode]:
        if src not in self.g:
            return set()
        return set(nx.descendants(self.g, src)) | {src}

    def paths_between(
        self, src: GroupNode, dst: GroupNode, *, max_paths: int = 1,
    ) -> list[list[GroupNode]]:
        if src not in self.g or dst not in self.g:
            return []
        out: list[list[GroupNode]] = []
        for path in nx.all_simple_paths(self.g, src, dst):
            out.append(list(path))
            if len(out) >= max_paths:
                break
        out.sort(key=len)
        return out


# --- construction -------------------------------------------------------


def _copy_into(big: nx.DiGraph, tg: TaintGraph, *, index: int) -> None:
    for n, attrs in tg.g.nodes(data=True):
        big.add_node(GroupNode(index, n), **attrs)
    for u, v, data in tg.g.edges(data=True):
        big.add_edge(
            GroupNode(index, u), GroupNode(index, v),
            kinds=set(data.get("kinds", ())),
        )


def _add_scratch_bridges(big: nx.DiGraph, members: list[TaintGraph]) -> None:
    """Scratch sharing — taint reaching a ``store N`` reaches a sibling that
    reads that slot. Two read forms (both enforce the AVM ``i < k`` rule):

    - ``gload i N`` — static sibling index + slot: bridge member ``i``'s
      ``store N`` to it precisely.
    - ``gloads N`` — static slot, sibling index popped from the stack: the index
      isn't known statically, so conservatively bridge EVERY earlier member's
      ``store N``. (``gloadss`` has a dynamic slot too -> left unbridged.)"""
    for k, tg_k in enumerate(members):
        for gnode in tg_k.find(op="gload"):
            parts = (tg_k.immediates_of(gnode) or "").split()
            if len(parts) != 2:
                continue
            try:
                i, slot = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            if not 0 <= i < k:                # AVM: only an earlier sibling
                continue
            for store in members[i].find(op="store", immediates=str(slot)):
                big.add_edge(GroupNode(i, store), GroupNode(k, gnode), kinds={"gload"})
        for gnode in tg_k.find(op="gloads"):  # dynamic index -> any earlier member
            slot = (tg_k.immediates_of(gnode) or "").strip()
            if not slot:
                continue
            for i in range(k):
                for store in members[i].find(op="store", immediates=slot):
                    big.add_edge(GroupNode(i, store), GroupNode(k, gnode), kinds={"gload"})


def _add_log_bridges(big: nx.DiGraph, members: list[TaintGraph]) -> None:
    """Log channel — a sibling reads what an earlier member logged. For each
    ``gtxn i LastLog`` / ``gtxna i Logs j`` in member ``k`` (``i < k``), bridge
    every ``log`` in member ``i`` to it (the group analog of xcontract's
    appcall-return ``log -> Logs`` bridge)."""
    for k, tg_k in enumerate(members):
        for op in ("gtxn", "gtxna"):
            for rnode in tg_k.find(op=op):
                parts = (tg_k.immediates_of(rnode) or "").split()
                if len(parts) < 2:
                    continue
                try:
                    i = int(parts[0])
                except ValueError:
                    continue
                if parts[1] not in ("LastLog", "Logs") or not 0 <= i < k:
                    continue
                for lognode in members[i].find(op="log"):
                    big.add_edge(GroupNode(i, lognode), GroupNode(k, rnode), kinds={"log"})


# --- cross-member taint detector ---------------------------------------


@dataclass(frozen=True)
class GroupTaintFinding:
    """An attacker-controlled input in one group member that reaches a sensitive
    sink in ANOTHER member via shared scratch (``store`` -> ``gload``)."""

    source: GroupNode
    sink: GroupNode
    sink_name: str
    path: tuple

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


def _sensitive_sinks(gtg: GroupTaintGraph) -> list[tuple[GroupNode, str]]:
    out: list[tuple[GroupNode, str]] = []
    for gn in gtg.nodes():
        op = gtg.op_of(gn)
        imm = gtg.immediates_of(gn)
        if op == "itxn_field" and imm in SENSITIVE_ITXN_FIELDS:
            out.append((gn, f"itxn_field {imm}"))
        elif op in STATE_WRITE_OPS:
            out.append((gn, op))
    return out


def _attacker_sources(gtg: GroupTaintGraph) -> list[GroupNode]:
    """User-controlled arg reads in any member — the whole group is attacker-
    assembled, so a member's own ``ApplicationArgs`` (``txn``/``txna``) AND a
    sibling's args read via ``gtxn i ApplicationArgs`` / ``gtxna`` are in scope."""
    out: list[GroupNode] = []
    for idx, tg in enumerate(gtg.members):
        for op in ("txna", "txn", "gtxn", "gtxna"):
            for n in tg.find(op=op):
                if "ApplicationArgs" in (tg.immediates_of(n) or ""):
                    out.append(GroupNode(idx, n))
    return out


def group_taint_findings(gtg: GroupTaintGraph) -> list[GroupTaintFinding]:
    """Report attacker-controlled inputs that reach a sensitive sink in a
    DIFFERENT group member — i.e. flows that cross a ``store`` -> ``gload``
    bridge. Intra-member flows are the single-program detectors' job; here we
    report exactly the group-scratch capability the bridges add."""
    sinks = _sensitive_sinks(gtg)
    findings: list[GroupTaintFinding] = []
    for src in _attacker_sources(gtg):
        reach = gtg.reachable_from(src)
        for sink_gn, name in sinks:
            if sink_gn.index == src.index or sink_gn not in reach:
                continue                      # intra-member, or unreachable
            paths = gtg.paths_between(src, sink_gn, max_paths=1)
            path = tuple(paths[0]) if paths else (src, sink_gn)
            findings.append(GroupTaintFinding(
                source=src, sink=sink_gn, sink_name=name, path=path,
            ))
    findings.sort(key=lambda f: (repr(f.source), repr(f.sink)))
    return findings


def render_group_taint(findings: list[GroupTaintFinding]) -> str:
    if not findings:
        return "(no cross-group taint findings)"
    return "\n".join(f.pretty() for f in findings)
