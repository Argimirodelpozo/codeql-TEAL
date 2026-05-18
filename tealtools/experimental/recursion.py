"""Detect recursive subroutines via the call-graph SCCs.

A subroutine that participates in a cycle in the static call graph
is either directly self-recursive (``callsub`` to itself) or
mutually recursive (A→B→…→A). In TEAL, recursion is almost always
unintentional — the language is stack-machine-based with no proper
tail-call optimisation, so deep recursion blows the call stack
quickly. Flagging recursive subs is a useful security/correctness
check.

Returns SCCs of size > 1 *and* singleton SCCs that have a self-loop.
"""
from __future__ import annotations

import networkx as nx

from ..control_tree import (
    build_control_tree, ProgramR, BlockR, Region,
)
from ..ssa import BasicBlock, SSAProgram


def call_graph(prog: SSAProgram) -> nx.DiGraph:
    """Build the subroutine call graph: nodes are entry BBs, edges
    are ``caller_entry → callee_entry`` for each ``callsub`` site
    in the caller's body. The :class:`ProgramR.subroutines` map
    gives us the structure; we walk each subroutine's region tree
    looking for ``BlockR`` nodes whose BBs end in ``callsub``."""
    tree = build_control_tree(prog)
    g = nx.DiGraph()
    if not isinstance(tree, ProgramR):
        return g
    for entry_bb in tree.subroutines:
        g.add_node(entry_bb)
    for entry_bb, body_region in tree.subroutines.items():
        for r in body_region.walk():
            if not isinstance(r, BlockR):
                continue
            bb = r.bb
            if (
                bb.assignments
                and bb.assignments[-1].op == "callsub"
                and bb.successors
            ):
                callee = bb.successors[0]
                if callee in tree.subroutines:
                    g.add_edge(entry_bb, callee)
    return g


def recursive_subroutines(prog: SSAProgram) -> list[list[BasicBlock]]:
    """List of recursion cycles: each entry is the BBs participating
    in one cycle. Singletons reported only when self-recursive."""
    g = call_graph(prog)
    cycles: list[list[BasicBlock]] = []
    for scc in nx.strongly_connected_components(g):
        scc = list(scc)
        if len(scc) > 1:
            cycles.append(scc)
        elif len(scc) == 1 and g.has_edge(scc[0], scc[0]):
            cycles.append(scc)
    return cycles


def render(prog: SSAProgram) -> str:
    """Human-readable report. Empty string when no recursion is found."""
    cycles = recursive_subroutines(prog)
    if not cycles:
        return "(no recursive subroutines)"
    out: list[str] = [f"{len(cycles)} recursive subroutine cycle(s):"]
    for i, cycle in enumerate(cycles):
        out.append(f"  cycle {i}:")
        for bb in cycle:
            if bb.assignments:
                loc = bb.assignments[0].location
                out.append(f"    {loc.file}:L{loc.line}")
            else:
                out.append("    <bb with no assignments>")
    return "\n".join(out)
