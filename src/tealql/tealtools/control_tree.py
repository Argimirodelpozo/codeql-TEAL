"""Structural analysis (Sharir / Allen-Cocke): lift the CFG into a **control
tree** of typed regions — loops collapsed innermost-first, then sequence /
if / switch pattern reductions — so analyses fold instead of iterating.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

import networkx as nx

from .cfg import CFG
from .loops import find_loops, Loop, _bb_sort_key
from .ssa import BasicBlock, SSAProgram
# identify_subroutines is re-exported here — public API at this name.
from .subroutines import _terminator_op, identify_subroutines  # noqa: F401


# ---------------------------------------------------------------------------
# Region types
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Region:
    """Base control-tree node; equality is identity, so structurally-identical
    regions stay distinct dict/set keys."""

    kind: str = field(init=False, default="region")

    def children(self) -> list["Region"]:
        """Direct child regions in execution order (``[]`` for leaves)."""
        return []

    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Every ``BasicBlock`` reachable inside this region."""
        for c in self.children():
            yield from c.basic_blocks()

    def walk(self) -> Iterator["Region"]:
        """Pre-order traversal of self + all descendants."""
        yield self
        for c in self.children():
            yield from c.walk()


@dataclass(eq=False)
class BlockR(Region):
    bb: BasicBlock
    kind: str = field(init=False, default="block")

    def basic_blocks(self) -> Iterator[BasicBlock]:
        yield self.bb


@dataclass(eq=False)
class SequenceR(Region):
    parts: list[Region]
    kind: str = field(init=False, default="sequence")

    def children(self) -> list[Region]:
        return list(self.parts)


@dataclass(eq=False)
class IfR(Region):
    cond: Region
    then_branch: Region
    kind: str = field(init=False, default="if")

    def children(self) -> list[Region]:
        return [self.cond, self.then_branch]


@dataclass(eq=False)
class IfElseR(Region):
    cond: Region
    then_branch: Region
    else_branch: Region
    kind: str = field(init=False, default="ifelse")

    def children(self) -> list[Region]:
        return [self.cond, self.then_branch, self.else_branch]


@dataclass(eq=False)
class SwitchR(Region):
    cond: Region
    cases: list[Region]
    kind: str = field(init=False, default="switch")

    def children(self) -> list[Region]:
        return [self.cond, *self.cases]


@dataclass(eq=False)
class GuardR(Region):
    """``cond`` with one terminal ``exit_arm`` peeled off (no outgoing edges —
    ``retsub`` / ``return`` / ``err``); it never flows back, so the
    continuation is the only forward-flow successor."""

    cond: Region
    exit_arm: Region
    kind: str = field(init=False, default="guard")

    def children(self) -> list[Region]:
        return [self.cond, self.exit_arm]


@dataclass(eq=False)
class LoopR(Region):
    body: Region
    loop: Loop  # original SCC info — back-edges, entries, etc.
    kind: str = field(init=False, default="loop")

    def children(self) -> list[Region]:
        return [self.body]


@dataclass(eq=False)
class ImproperR(Region):
    """Irreducible sub-graph — couldn't be reduced to a typed region.

    HAZARD: nothing about its control flow is known. A fold that treats it as
    straight-line UNDER-counts; consumers must fall back to a worst-case bound."""

    nodes: list[Region]
    edges: list[tuple[Region, Region]]
    entries: list[Region]
    kind: str = field(init=False, default="improper")

    def children(self) -> list[Region]:
        return list(self.nodes)


@dataclass(eq=False)
class ProgramR(Region):
    """Multi-program root: one region per independent program (a source can hold
    approval + clear-state, which never call each other) in entry order, plus
    each subroutine's region and its ``(cost, submits)`` summary keyed by entry
    BB — what cost analysis charges at a ``callsub``."""

    programs: list[Region]
    subroutines: dict[BasicBlock, Region] = field(default_factory=dict)
    subroutine_summaries: dict[BasicBlock, tuple[int, int]] = field(
        default_factory=dict
    )
    kind: str = field(init=False, default="program")

    def children(self) -> list[Region]:
        return list(self.programs) + list(self.subroutines.values())


def build_control_tree(prog: SSAProgram) -> Region:
    """Lift ``prog``'s CFG into a control tree: subroutines reduce into their own
    regions and each ``callsub → entry`` / ``retsub → caller`` edge is cut and
    replaced by a synthetic ``callsub → continuation``, so the main flow stays
    connected and each post-cut component is one program.

    Returns a BARE region, not a :class:`ProgramR`, when the source has one
    program and no subroutines."""
    cfg = CFG.of(prog)

    # ---- Interprocedural pre-pass: identify subroutines + cut edges. ----
    sub_info = identify_subroutines(prog)
    callsub_to_continuation = sub_info["continuations"]  # callsub_bb → continuation_bb
    sub_entries = sub_info["entries"]                    # set of subroutine entry BBs
    sub_bodies = sub_info["bodies"]                       # entry → set of body BBs

    # Cut callsub BB → callee-entry and retsub BB → caller-continuation, once,
    # for both the BB-level loop CFG and the Region-level reduction graph.
    cut_edges: set[tuple[BasicBlock, BasicBlock]] = set()
    for bb in prog.blocks.values():
        if _terminator_op(bb) in ("callsub", "retsub"):
            for s in bb.successors:
                cut_edges.add((bb, s))

    # Loop detection runs on the CUT CFG (recursion / mutual calls would
    # otherwise read as loops) but must ALSO carry the synthetic continuation
    # edges: without them a callsub dead-ends, a loop whose body calls has no
    # cycle at all, and it flattens to a SequenceR — its iteration cost folds
    # as a single pass, an UNDER-count reported as exact.
    cut_cfg = nx.DiGraph()
    for bb in prog.blocks.values():
        cut_cfg.add_node(bb)
    for bb in prog.blocks.values():
        for s in bb.successors:
            if (bb, s) in cut_edges:
                continue
            cut_cfg.add_edge(bb, s)
    for callsub_bb, cont_bb in callsub_to_continuation.items():
        if cont_bb is not None:
            cut_cfg.add_edge(callsub_bb, cont_bb)
    forest = find_loops(prog, graph=cut_cfg)

    # Region graph: one BlockR per BB, same cuts, same synthetic edges.
    bb_to_region: dict[BasicBlock, Region] = {
        bb: BlockR(bb=bb) for bb in cfg.blocks
    }

    g = nx.DiGraph()
    for r in bb_to_region.values():
        g.add_node(r)
    for bb, r in bb_to_region.items():
        for s in bb.successors:
            if (bb, s) in cut_edges:
                continue
            g.add_edge(r, bb_to_region[s])
    # Synthetic edges so callsub doesn't dead-end.
    for callsub_bb, cont_bb in callsub_to_continuation.items():
        if cont_bb is None:
            continue
        g.add_edge(bb_to_region[callsub_bb], bb_to_region[cont_bb])

    # Phase 1: collapse loops innermost-first — each body sub-graph (back-edges
    # excluded) is reduced, wrapped as a LoopR, contracted to one node.
    for loop in forest.innermost_first():
        # Stable BB order so subgraph insertion order is reproducible per run.
        ordered_nodes = sorted(loop.nodes, key=_bb_sort_key)
        body_regions = [
            bb_to_region[bb] for bb in ordered_nodes if bb in bb_to_region
        ]
        if not body_regions:
            continue
        body_g = g.subgraph(body_regions).copy()
        for (u_bb, v_bb) in sorted(
            loop.back_edges, key=lambda e: (_bb_sort_key(e[0]), _bb_sort_key(e[1]))
        ):
            u_r = bb_to_region.get(u_bb)
            v_r = bb_to_region.get(v_bb)
            if u_r is None or v_r is None:
                continue
            if body_g.has_edge(u_r, v_r):
                body_g.remove_edge(u_r, v_r)
        body_region = _reduce(body_g)
        loop_region = LoopR(body=body_region, loop=loop)
        _contract_nodes(g, body_regions, loop_region)
        # Re-map BBs so a later (outer) loop's body-region list still resolves.
        for bb in ordered_nodes:
            if bb in bb_to_region:
                bb_to_region[bb] = loop_region

    # Phase 2: reduce each weakly-connected component. Post-cut, a subroutine is
    # its own component (rooted at its entry BB); the rest are main programs.
    components = list(nx.weakly_connected_components(g))
    main_programs: list[Region] = []
    subroutines: dict[BasicBlock, Region] = {}

    def comp_key(comp: set[Region]) -> tuple:
        keys = []
        for r in comp:
            for bb in r.basic_blocks():
                keys.append(_bb_sort_key(bb))
        return min(keys) if keys else ("", 0)
    components.sort(key=comp_key)

    for comp in components:
        # Does this component contain a subroutine entry BB?
        comp_bbs: set[BasicBlock] = set()
        for r in comp:
            for bb in r.basic_blocks():
                comp_bbs.add(bb)
        sub_entry_in_comp = comp_bbs & sub_entries
        comp_region = _reduce(g.subgraph(comp).copy())
        if sub_entry_in_comp and len(sub_entry_in_comp) == 1:
            entry_bb = next(iter(sub_entry_in_comp))
            subroutines[entry_bb] = comp_region
        else:
            main_programs.append(comp_region)

    summaries = _compute_subroutine_summaries(prog, sub_entries, sub_bodies)

    # One program, no subroutines → hand back the bare region.
    if not subroutines and len(main_programs) == 1:
        return main_programs[0]
    return ProgramR(
        programs=main_programs,
        subroutines=subroutines,
        subroutine_summaries=summaries,
    )


def _compute_subroutine_summaries(
    prog: SSAProgram,
    entries: set[BasicBlock],
    bodies: dict[BasicBlock, set[BasicBlock]],
) -> dict[BasicBlock, tuple[int, int]]:
    """Per-subroutine ``(cost, submits)``, folded bottom-up over the topo-sorted
    call graph with each ``callsub`` charged its callee's summary.

    A recursive call graph falls back to a round-capped fixed point — still a
    sound UPPER bound."""
    from .cost_analysis import opcode_cost   # local: module-level would cycle

    # Build call graph (subroutine → set of called sub entries).
    call_graph: dict[BasicBlock, set[BasicBlock]] = {e: set() for e in entries}
    for entry, body in bodies.items():
        for bb in body:
            if not bb.assignments:
                continue
            if _terminator_op(bb) != "callsub":
                continue
            if not bb.successors:
                continue
            callee = bb.successors[0]
            if callee in entries and callee is not entry:
                call_graph[entry].add(callee)

    g = nx.DiGraph()
    for e in entries:
        g.add_node(e)
        for callee in call_graph[e]:
            g.add_edge(e, callee)

    summaries: dict[BasicBlock, tuple[int, int]] = {e: (0, 0) for e in entries}
    try:
        order = list(nx.topological_sort(g.reverse()))
    except nx.NetworkXUnfeasible:
        # Recursive call graph — fixed-point with a generous round cap.
        order = sorted(entries, key=_bb_sort_key)
        for _ in range(min(len(entries), 32)):
            changed = False
            for e in order:
                new = _summarize_body_with_calls(bodies[e], summaries, opcode_cost)
                if new != summaries[e]:
                    summaries[e] = new
                    changed = True
            if not changed:
                break
        return summaries

    for entry in order:
        summaries[entry] = _summarize_body_with_calls(
            bodies[entry], summaries, opcode_cost
        )
    return summaries


def _summarize_body_with_calls(body, summaries, opcode_cost):
    """Sum body BB op costs, charging each ``callsub`` its callee's summary."""
    cost = 0
    submits = 0
    for bb in body:
        for a in bb.assignments:
            cost += opcode_cost(a.op)
            if a.op in ("itxn_submit", "itxn_next"):
                submits += 1
            elif a.op == "callsub" and bb.successors:
                callee = bb.successors[0]
                sc, ss = summaries.get(callee, (0, 0))
                cost += sc
                submits += ss
    return cost, submits


# ---------------------------------------------------------------------------
# Reduction core
# ---------------------------------------------------------------------------


def _reduce(g: nx.DiGraph) -> Region:
    """Reduce an acyclic region graph to one Region by repeated pattern
    matching; whatever won't reduce comes back as an :class:`ImproperR`."""
    while g.number_of_nodes() > 1:
        progressed = False
        for n in list(g.nodes):
            if n not in g.nodes:
                continue
            if _try_sequence(g, n):
                progressed = True
                break
            if _try_if_else(g, n):
                progressed = True
                break
            if _try_if_then(g, n):
                progressed = True
                break
            if _try_switch(g, n):
                progressed = True
                break
            if _try_guard(g, n):
                progressed = True
                break
        if not progressed:
            break

    if g.number_of_nodes() == 1:
        return next(iter(g.nodes))

    # Couldn't reduce further — wrap as Improper.
    entries = [n for n in g.nodes if g.in_degree(n) == 0]
    if not entries:
        # Every node has a predecessor: irreducible loop, no clear entry.
        entries = [next(iter(g.nodes))]
    return ImproperR(
        nodes=list(g.nodes),
        edges=list(g.edges),
        entries=entries,
    )


# --- Pattern matchers -------------------------------------------------------
#
# Each ``_try_*`` returns True if it contracted a region rooted at ``n``,
# else False.


def _try_sequence(g: nx.DiGraph, n: Region) -> bool:
    """Sequence: ``n → m`` is the only edge out of ``n`` and the only edge into
    ``m``. Collapse to a ``SequenceR``."""
    if g.out_degree(n) != 1:
        return False
    m = next(iter(g.successors(n)))
    if m is n:
        return False
    if g.in_degree(m) != 1:
        return False
    if g.has_edge(m, n):
        # ``n → m → n`` is a CYCLE, not a sequence: contracting it hides the
        # back edge and folds a loop as one iteration. Leave it for loop
        # collapse / the Improper fallback.
        return False
    seq = _flatten_sequence([n, m])
    _replace(g, [n, m], seq)
    return True


def _try_if_else(g: nx.DiGraph, n: Region) -> bool:
    """IfElse: ``n``'s two successors are simple arms sharing one join."""
    if g.out_degree(n) != 2:
        return False
    a, b = list(g.successors(n))
    if a is b or a is n or b is n:
        return False
    if not _is_simple_arm(g, n, a):
        return False
    if not _is_simple_arm(g, n, b):
        return False
    j_a = next(iter(g.successors(a)))
    j_b = next(iter(g.successors(b)))
    if j_a is not j_b:
        return False
    ifelse = IfElseR(cond=n, then_branch=a, else_branch=b)
    _replace(g, [n, a, b], ifelse, joins_to=j_a)
    return True


def _try_if_then(g: nx.DiGraph, n: Region) -> bool:
    """IfThen: one of ``n``'s two successors is a simple arm whose successor is
    the other — that arm becomes the then-branch, the other the join."""
    if g.out_degree(n) != 2:
        return False
    a, b = list(g.successors(n))
    if a is b or a is n or b is n:
        return False
    for then_arm, join in ((a, b), (b, a)):
        if not _is_simple_arm(g, n, then_arm):
            continue
        succ = next(iter(g.successors(then_arm)))
        if succ is not join:
            continue
        if_r = IfR(cond=n, then_branch=then_arm)
        _replace(g, [n, then_arm], if_r, joins_to=join)
        return True
    return False


def _try_guard(g: nx.DiGraph, n: Region) -> bool:
    """Peel one terminal successor of ``n`` (out-degree 0, reached only from
    ``n``) into a ``GuardR``, keeping ``n``'s other successors — repeated at any
    out-degree ≥ 2, this drives dispatch chains and ``err`` bailouts towards an
    If/IfElse/Switch shape."""
    if g.out_degree(n) < 2:
        return False
    for tail in list(g.successors(n)):
        if tail is n:
            continue
        if g.in_degree(tail) != 1:
            continue
        if g.out_degree(tail) != 0:
            continue
        guard = GuardR(cond=n, exit_arm=tail)
        other_succs = [s for s in g.successors(n) if s is not tail]
        preds = [
            p for p in g.predecessors(n) if p is not n and p is not tail
        ]
        g.remove_node(n)
        g.remove_node(tail)
        g.add_node(guard)
        for p in preds:
            g.add_edge(p, guard)
        for s in other_succs:
            g.add_edge(guard, s)
        return True
    return False


def _try_switch(g: nx.DiGraph, n: Region) -> bool:
    """Switch: ``n``'s ≥3 successors are all simple arms sharing one join."""
    if g.out_degree(n) < 3:
        return False
    arms = list(g.successors(n))
    if len(set(arms)) != len(arms):
        return False
    if any(a is n for a in arms):
        return False
    joins: list[Region] = []
    for a in arms:
        if not _is_simple_arm(g, n, a):
            return False
        joins.append(next(iter(g.successors(a))))
    if len(set(id(j) for j in joins)) != 1:
        return False
    join = joins[0]
    sw = SwitchR(cond=n, cases=arms)
    _replace(g, [n, *arms], sw, joins_to=join)
    return True


def _is_simple_arm(g: nx.DiGraph, head: Region, arm: Region) -> bool:
    """``arm`` is reached only from ``head`` and has exactly one successor."""
    if g.in_degree(arm) != 1:
        return False
    if next(iter(g.predecessors(arm))) is not head:
        return False
    if g.out_degree(arm) != 1:
        return False
    return True


# --- Graph contraction helpers ---------------------------------------------


def _flatten_sequence(parts: list[Region]) -> SequenceR:
    flat: list[Region] = []
    for p in parts:
        if isinstance(p, SequenceR):
            flat.extend(p.parts)
        else:
            flat.append(p)
    return SequenceR(parts=flat)


def _replace(
    g: nx.DiGraph,
    consumed: list[Region],
    new: Region,
    *,
    joins_to: Optional[Region] = None,
) -> None:
    """Contract ``consumed`` into ``new``, which inherits ``consumed[0]``'s
    predecessors and — unless ``joins_to`` names the join — ``consumed[-1]``'s
    successors, both minus the consumed set."""
    head, tail = consumed[0], consumed[-1]
    consumed_set = set(consumed)
    preds = [p for p in g.predecessors(head) if p not in consumed_set]
    if joins_to is None:
        succs = [s for s in g.successors(tail) if s not in consumed_set]
    else:
        succs = [joins_to]
    for node in consumed:
        g.remove_node(node)
    g.add_node(new)
    for p in preds:
        g.add_edge(p, new)
    for s in succs:
        g.add_edge(new, s)


def _contract_nodes(
    g: nx.DiGraph, nodes: list[Region], replacement: Region
) -> None:
    """Replace ``nodes`` with one ``replacement`` — external edges redirect to
    it, intra-cluster edges drop — deduping in ORDER, since sets keyed on
    identity-hashed Regions would vary the edge order run to run."""
    node_set = set(nodes)
    in_preds: list[Region] = []
    out_succs: list[Region] = []
    seen_p: set[int] = set()
    seen_s: set[int] = set()
    for n in nodes:
        for p in g.predecessors(n):
            if p in node_set or id(p) in seen_p:
                continue
            seen_p.add(id(p))
            in_preds.append(p)
        for s in g.successors(n):
            if s in node_set or id(s) in seen_s:
                continue
            seen_s.add(id(s))
            out_succs.append(s)
    for n in nodes:
        g.remove_node(n)
    g.add_node(replacement)
    for p in in_preds:
        g.add_edge(p, replacement)
    for s in out_succs:
        g.add_edge(replacement, s)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def pretty(region: Region, indent: int = 0) -> str:
    """Indented textual dump of the control tree."""
    pad = "  " * indent
    if isinstance(region, BlockR):
        ops = ",".join(a.op for a in region.bb.assignments)
        return f"{pad}block lines={[a.location.line for a in region.bb.assignments]} ops=[{ops}]"
    if isinstance(region, SequenceR):
        body = "\n".join(pretty(p, indent + 1) for p in region.parts)
        return f"{pad}sequence\n{body}"
    if isinstance(region, IfR):
        return (
            f"{pad}if\n"
            f"{pretty(region.cond, indent + 1)}\n"
            f"{pad}  then:\n"
            f"{pretty(region.then_branch, indent + 2)}"
        )
    if isinstance(region, IfElseR):
        return (
            f"{pad}ifelse\n"
            f"{pretty(region.cond, indent + 1)}\n"
            f"{pad}  then:\n"
            f"{pretty(region.then_branch, indent + 2)}\n"
            f"{pad}  else:\n"
            f"{pretty(region.else_branch, indent + 2)}"
        )
    if isinstance(region, GuardR):
        return (
            f"{pad}guard\n"
            f"{pretty(region.cond, indent + 1)}\n"
            f"{pad}  exit:\n"
            f"{pretty(region.exit_arm, indent + 2)}"
        )
    if isinstance(region, SwitchR):
        cases = "\n".join(
            f"{pad}  case {i}:\n{pretty(c, indent + 2)}"
            for i, c in enumerate(region.cases)
        )
        return f"{pad}switch\n{pretty(region.cond, indent + 1)}\n{cases}"
    if isinstance(region, LoopR):
        return f"{pad}loop ({len(region.loop.nodes)} bbs)\n{pretty(region.body, indent + 1)}"
    if isinstance(region, ImproperR):
        entry_ids = {id(e) for e in region.entries}
        body = "\n".join(
            f"{pad}  [entry] {pretty(n, indent + 1).lstrip()}"
            if id(n) in entry_ids
            else pretty(n, indent + 1)
            for n in region.nodes
        )
        return (
            f"{pad}improper ({len(region.nodes)} nodes, "
            f"{len(region.edges)} edges)\n{body}"
        )
    if isinstance(region, ProgramR):
        body = "\n".join(
            f"{pad}  program {i}:\n{pretty(p, indent + 2)}"
            for i, p in enumerate(region.programs)
        )
        return f"{pad}programs ({len(region.programs)})\n{body}"
    return f"{pad}<unknown region {type(region).__name__}>"
