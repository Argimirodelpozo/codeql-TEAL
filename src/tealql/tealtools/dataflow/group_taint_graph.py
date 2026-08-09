"""Taint across the members of one atomic group — the horizontal sibling axis,
bridged over shared scratch (``store N`` -> ``gload i N``) and the log channel.

This is the cross-group scratch read that makes a ``store`` with no in-program
load still live; DSE must never drop it. Group members have no call/return, and
the group is assembled EXTERNALLY, so :meth:`GroupTaintGraph.build` takes an
ORDERED list where the list index IS the group position.

HAZARD: the AVM only lets a member read an EARLIER sibling's scratch/effects, so
every bridge is gated on ``i < k``; bridging forward invents flows that cannot
happen. Dynamic member/slot selectors conservatively range over every earlier
member and compatible writer."""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ._nx_view import NxGraphView, copy_into, sensitive_sinks

from ..language.avm import TXN_FIELD_OPS, txn_field_name
from ..ssa import SSAProgram
from .taint_graph import Node, TaintGraph


@dataclass(frozen=True)
class GroupNode:
    """A taint node qualified by the group index of the member it lives in."""

    index: int
    inner: Node

    def __repr__(self) -> str:
        return f"g{self.index}:{self.inner!r}"


@dataclass
class GroupTaintGraph(NxGraphView):
    """Per-member :class:`TaintGraph`\\ s merged into one graph, plus the
    ``store -> gload`` scratch bridges between siblings."""

    g: nx.DiGraph
    members: list[TaintGraph]

    @classmethod
    def build(cls, member_progs: list[SSAProgram]) -> "GroupTaintGraph":
        """Build from an ORDERED member list — ``member_progs[i]`` is group txn ``i``."""
        members = [TaintGraph.of(p) for p in member_progs]
        big: nx.DiGraph = nx.DiGraph()
        for idx, tg in enumerate(members):
            _copy_into(big, tg, index=idx)
        _add_scratch_bridges(big, members)
        _add_log_bridges(big, members)
        return cls(g=big, members=members)

    # --- queries -------------------------------------------------------

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
    copy_into(big, tg, lambda n: GroupNode(index, n))


def _add_scratch_bridges(big: nx.DiGraph, members: list[TaintGraph]) -> None:
    """Bridge taint from a ``store N`` to the siblings that read that slot.

    ``gload i N`` pins member and slot. ``gloads N`` has a dynamic member;
    ``gloadss`` has dynamic member and slot. A dynamic ``stores`` writer may
    target every slot, so it participates in all three read forms."""

    def writers(tg: TaintGraph, slot: str | None):
        out = list(tg.find(op="stores"))
        if slot is None:
            out.extend(tg.find(op="store"))
        else:
            out.extend(tg.find(op="store", immediates=slot))
        return out

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
            for store in writers(members[i], str(slot)):
                big.add_edge(GroupNode(i, store), GroupNode(k, gnode), kinds={"gload"})
        for gnode in tg_k.find(op="gloads"):  # dynamic index -> any earlier member
            slot = (tg_k.immediates_of(gnode) or "").strip()
            if not slot:
                continue
            for i in range(k):
                for store in writers(members[i], slot):
                    big.add_edge(GroupNode(i, store), GroupNode(k, gnode), kinds={"gload"})
        for gnode in tg_k.find(op="gloadss"):
            for i in range(k):
                for store in writers(members[i], None):
                    big.add_edge(GroupNode(i, store), GroupNode(k, gnode), kinds={"gload"})


def _add_log_bridges(big: nx.DiGraph, members: list[TaintGraph]) -> None:
    """Bridge every ``log`` in member ``i`` to a sibling's read of it (``i < k``)."""
    for k, tg_k in enumerate(members):
        # Immediate-group forms bridge one member. Dynamic-group forms bridge
        # every earlier member: the selector's def-use edge separately carries
        # taint from the choice itself into the read node.
        for op in ("gtxn", "gtxna", "gtxnas"):
            for rnode in tg_k.find(op=op):
                imms = tg_k.immediates_of(rnode) or ""
                parts = imms.split()
                if len(parts) < 2:
                    continue
                try:
                    i = int(parts[0])
                except ValueError:
                    continue
                if txn_field_name(op, imms) not in ("LastLog", "Logs") or not 0 <= i < k:
                    continue
                for lognode in members[i].find(op="log"):
                    big.add_edge(GroupNode(i, lognode), GroupNode(k, rnode), kinds={"log"})
        for op in ("gtxns", "gtxnsa", "gtxnsas"):
            for rnode in tg_k.find(op=op):
                imms = tg_k.immediates_of(rnode) or ""
                if txn_field_name(op, imms) not in ("LastLog", "Logs"):
                    continue
                for i in range(k):
                    for lognode in members[i].find(op="log"):
                        big.add_edge(GroupNode(i, lognode), GroupNode(k, rnode), kinds={"log"})


# --- cross-member taint detector ---------------------------------------


@dataclass(frozen=True)
class GroupTaintFinding:
    """An input in one group member reaching a sensitive sink in ANOTHER member."""

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
    return sensitive_sinks(gtg)


def _attacker_sources(gtg: GroupTaintGraph) -> list[GroupNode]:
    """Arg reads in any member — the whole group is attacker-assembled, so a
    sibling's args are as controlled as the member's own."""
    out: list[GroupNode] = []
    for idx, tg in enumerate(gtg.members):
        # Every txn-family read form, not a hand-listed four: this only asks
        # WHICH FIELD is read, so the dynamic-index forms (`txnas`, `gtxns*`,
        # `gtxnas`) count too — and omitting them silently dropped attacker
        # sources that a loop over ApplicationArgs produces.
        for op in TXN_FIELD_OPS:
            for n in tg.find(op=op):
                if txn_field_name(op, tg.immediates_of(n) or "") == "ApplicationArgs":
                    out.append(GroupNode(idx, n))
    return out


def group_taint_findings(gtg: GroupTaintGraph) -> list[GroupTaintFinding]:
    """Report inputs reaching a sensitive sink in a DIFFERENT member — intra-member
    flows belong to the single-program detectors and are excluded here."""
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
