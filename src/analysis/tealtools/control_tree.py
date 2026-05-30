"""Structural analysis (Sharir / Allen-Cocke) — lift the CFG into a
**control tree** of typed regions so analyses become folds rather
than worklists.

Each region is one of:

- :class:`BlockR` — leaf, a single basic block.
- :class:`SequenceR` — ordered list of regions executed in sequence.
- :class:`IfR` — head with a conditional skip (one branch falls
  through to the join, the other passes through ``then_branch``).
- :class:`IfElseR` — head with two arms joining at a common point.
- :class:`SwitchR` — head with N≥3 arms joining at a common point.
- :class:`LoopR` — natural loop with a body region (kind = ``"while"``,
  ``"dowhile"``, or ``"loop"`` when the head-vs-tail distinction
  isn't clean).
- :class:`ImproperR` — irreducible region. Holds the raw sub-graph;
  consumers should fall back to a worst-case bound.

Pipeline (:func:`build_control_tree`):

1. Wrap each ``BasicBlock`` in a :class:`BlockR`.
2. Use :mod:`tealtools.loops` (SCC + sub-loop nesting) to identify
   every loop, innermost first. For each loop, recursively reduce
   its body sub-graph (back-edges excluded) into one region and
   wrap as a :class:`LoopR`; collapse the loop's BBs in the parent
   graph to that single node.
3. With the graph now acyclic, apply pattern reductions
   (sequence, if/else, switch) until a single root remains.
4. Anything that won't reduce becomes an :class:`ImproperR`.

Output: one :class:`Region` rooted at the program's entry — the
whole program is a single typed tree. Cost analysis, path
predicates, etc. can fold over it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

import networkx as nx

from .cfg import CFG
from .loops import find_loops, Loop, _bb_sort_key
from .ssa import _TERMINATOR_OPS, BasicBlock, SSAProgram


# ---------------------------------------------------------------------------
# Region types
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Region:
    """Base type for all control-tree nodes. Identity-based equality
    so each region is its own dict/set key — multiple structurally-
    identical regions in a tree are still distinct."""

    kind: str = field(init=False, default="region")

    def children(self) -> list["Region"]:
        """Direct child regions, in execution order where applicable.
        Leaf regions return ``[]``."""
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
    """``cond → [exit_arm, continuation]`` where ``exit_arm`` is a
    terminal region with no outgoing edges (e.g. a method body that
    ends in ``retsub`` / ``return`` / ``err``). The continuation
    becomes the only forward-flow successor; the exit arm executes
    only on the branch-taken path and doesn't flow back."""

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
    """Irreducible sub-graph — couldn't be reduced to a typed region."""

    nodes: list[Region]
    edges: list[tuple[Region, Region]]
    entries: list[Region]
    kind: str = field(init=False, default="improper")

    def children(self) -> list[Region]:
        return list(self.nodes)


@dataclass(eq=False)
class ProgramR(Region):
    """Multi-program root — a TEAL DB can hold several independent
    programs (e.g., approval + clear-state .teal files). Each
    program's CFG is its own connected component; they don't call
    each other, so analyses should treat them independently.

    ``programs`` lists each program's region in source-order by entry
    file/line. For single-program DBs the builder returns that
    program's region directly rather than wrapping it here.

    ``subroutines`` (when non-empty) maps each subroutine entry BB to
    its lifted region. The main programs reach subroutines via
    ``callsub`` ops; cost analysis uses :attr:`subroutine_summaries`
    to charge each ``callsub`` for the callee's per-execution cost.
    """

    programs: list[Region]
    subroutines: dict[BasicBlock, Region] = field(default_factory=dict)
    subroutine_summaries: dict[BasicBlock, tuple[int, int]] = field(
        default_factory=dict
    )
    kind: str = field(init=False, default="program")

    def children(self) -> list[Region]:
        return list(self.programs) + list(self.subroutines.values())


@dataclass(eq=False)
class SubroutineR(Region):
    """A lifted subroutine — single entry, body region, and a
    static ``(cost, submits)`` summary for use at every ``callsub``
    site."""

    entry_bb: BasicBlock
    body: Region
    cost: int
    submits: int
    kind: str = field(init=False, default="subroutine")

    def children(self) -> list[Region]:
        return [self.body]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def _terminator_op(bb: BasicBlock) -> Optional[str]:
    """Return the control-flow terminator op of ``bb``, or ``None`` if
    the BB has no terminator (e.g. fall-through end of program).

    Why we scan instead of using ``bb.assignments[-1].op``:
    after :meth:`SSAProgram.materialize_phis`, mat-phi copy assignments
    are inserted at the source line of the value-producing op. When that
    producer is itself a terminator (most importantly ``retsub``, which
    has an SSA output linking returned values to callers, and
    ``callsub``, whose outputs are the returned values), those copies
    land *after* the terminator in ``bb.assignments``. The terminator is
    no longer the last entry, and naive ``[-1]`` checks silently misclassify
    the BB as non-terminating — which broke the interprocedural edge cut.
    """
    for a in bb.assignments:
        if a.op in _TERMINATOR_OPS:
            return a.op
    return None


def build_control_tree(prog: SSAProgram) -> Region:
    """Lift ``prog``'s CFG into a control tree. The root region
    represents the entire DB.

    Subroutines (``callsub``-reachable BBs) are detected and lifted
    into their own :class:`SubroutineR` regions, then the main flow's
    CFG has each ``callsub → entry`` and ``retsub → caller`` edge
    cut and replaced with a synthetic ``callsub → continuation`` edge
    so the main program's flow is connected without the per-call-site
    fan-in/out at subroutine boundaries. Per-subroutine static
    ``(cost, submits)`` summaries (computed by topo-sorting the call
    graph) are stored on the returned :class:`ProgramR` for cost
    analyses to charge at each ``callsub`` site.

    Multi-program DBs (e.g. approval + clear-state .teal files in one
    DB) likewise produce one program per weakly-connected component
    of the post-cut graph; single-program DBs without subroutines get
    a bare region back."""
    cfg = CFG.of(prog)

    # ---- Interprocedural pre-pass: identify subroutines + cut edges. ----
    sub_info = _identify_subroutines(prog)
    callsub_to_continuation = sub_info["continuations"]  # callsub_bb → continuation_bb
    sub_entries = sub_info["entries"]                    # set of subroutine entry BBs
    sub_bodies = sub_info["bodies"]                       # entry → set of body BBs

    # Compute interprocedural edge cuts ONCE — used for both loop
    # detection (BB-level cut CFG) and the Region-level reduction graph.
    # Cut ``callsub`` BB → callee-entry, and ``retsub`` BB → caller-continuation.
    cut_edges: set[tuple[BasicBlock, BasicBlock]] = set()
    for bb in prog.blocks.values():
        if _terminator_op(bb) in ("callsub", "retsub"):
            for s in bb.successors:
                cut_edges.add((bb, s))

    # Loop detection has to run on the *cut* CFG — otherwise recursive
    # subs (and mutual-call pairs) create cross-sub cycles that get
    # misclassified as loops and pull multiple subs' BBs into one
    # LoopR.
    cut_cfg = nx.DiGraph()
    for bb in prog.blocks.values():
        cut_cfg.add_node(bb)
    for bb in prog.blocks.values():
        for s in bb.successors:
            if (bb, s) in cut_edges:
                continue
            cut_cfg.add_edge(bb, s)
    forest = find_loops(prog, graph=cut_cfg)

    # Initial Region graph: one BlockR per BB. Same cuts apply, plus
    # synthetic ``callsub → continuation`` edges so the main program
    # flows past each call site.
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

    # Phase 1: collapse loops innermost-first. Each loop's body
    # sub-graph (back-edges excluded) is recursively reduced and
    # wrapped as a LoopR; the loop's BBs in the parent graph are
    # replaced by that single node.
    for loop in forest.innermost_first():
        # Stable BB ordering so the resulting body-subgraph node /
        # edge insertion order is reproducible across runs.
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
        # Re-map BBs to the new region so any later (outer) loop's
        # body-region list still resolves.
        for bb in ordered_nodes:
            if bb in bb_to_region:
                bb_to_region[bb] = loop_region

    # Phase 2: split into weakly-connected components and reduce each.
    # After cutting callsub/retsub edges, each subroutine becomes its
    # own component (rooted at its entry BB). Top-level program(s) are
    # the components that include a CFG entry. We classify components,
    # reduce each, and stash subroutine bodies under their entry BB
    # for cost analysis to pull summaries from.
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

    # Topo-sort the call graph for subroutine-summary computation.
    summaries = _compute_subroutine_summaries(prog, sub_entries, sub_bodies)

    # If there are no subroutines and exactly one main program, return
    # the bare region (back-compat for simple programs).
    if not subroutines and len(main_programs) == 1:
        return main_programs[0]
    return ProgramR(
        programs=main_programs,
        subroutines=subroutines,
        subroutine_summaries=summaries,
    )


# ---------------------------------------------------------------------------
# Interprocedural pre-pass — identify subroutines and their continuations
# ---------------------------------------------------------------------------


def _identify_subroutines(prog: SSAProgram) -> dict:
    """Inspect the CFG for ``callsub`` / ``retsub`` ops and produce:

    - ``entries``: BBs that are direct successors of any ``callsub``-
      ending BB. These are the subroutine entry points.
    - ``bodies``: ``entry_bb → set[BB]`` — the intraprocedural-reachable
      BBs starting from each entry. We follow successor edges, but
      stop at ``retsub`` BBs (their successors leave the body) and
      don't enter other subroutine entries.
    - ``continuations``: ``callsub_bb → continuation_bb``. Heuristic:
      after ``callsub`` at line L, control returns to the BB whose
      first line is the smallest ``> L`` in the same file *and* is a
      successor of some ``retsub`` in the called subroutine. Captures
      the linear "after the call" code without following the long way
      around through the callee's retsub edges.
    """
    entries: set[BasicBlock] = set()
    callsub_target: dict[BasicBlock, BasicBlock] = {}
    retsub_targets_per_sub: dict[BasicBlock, set[BasicBlock]] = {}

    callsub_bbs: list[BasicBlock] = []
    retsub_bbs: list[BasicBlock] = []
    for bb in prog.blocks.values():
        last = _terminator_op(bb)
        if last == "callsub":
            callsub_bbs.append(bb)
            if bb.successors:
                callsub_target[bb] = bb.successors[0]
                entries.add(bb.successors[0])
        elif last == "retsub":
            retsub_bbs.append(bb)

    # Compute each subroutine's body via intraprocedural BFS from
    # its entry. Stop at retsub BBs (successors leave the body) and
    # at OTHER subroutine entries (don't cross into other callees).
    bodies: dict[BasicBlock, set[BasicBlock]] = {}
    for entry in entries:
        body: set[BasicBlock] = set()
        stack: list[BasicBlock] = [entry]
        while stack:
            bb = stack.pop()
            if bb in body:
                continue
            body.add(bb)
            last_op = _terminator_op(bb)
            if last_op == "retsub":
                continue  # successors are caller continuations
            for s in bb.successors:
                # Don't cross into another subroutine.
                if s in entries and s is not entry:
                    continue
                # Don't follow callsub→entry edges out of *this* sub.
                if last_op == "callsub" and s in entries:
                    continue
                stack.append(s)
        bodies[entry] = body
        retsub_targets_per_sub[entry] = {
            t for bb in body
            if _terminator_op(bb) == "retsub"
            for t in bb.successors
        }

    # Match each callsub to its continuation. Two layered heuristics
    # (first one to find a candidate wins):
    # 1. Source-order: smallest BB whose first line is strictly
    #    greater than the callsub's last line, in the same file.
    #    Compiled TEAL emits the continuation immediately after the
    #    callsub op, so this is robust as long as the linker doesn't
    #    interleave subroutine bodies between caller and continuation.
    # 2. Retsub-targeted: smallest line > callsub_line among the
    #    successors of any retsub in the called subroutine. Fallback
    #    for cases where the linker did interleave.
    bb_by_file_line: dict[str, list[BasicBlock]] = {}
    for bb in prog.blocks.values():
        if not bb.assignments:
            continue
        loc = bb.assignments[0].location
        bb_by_file_line.setdefault(loc.file, []).append(bb)
    for f in bb_by_file_line:
        bb_by_file_line[f].sort(key=lambda b: b.assignments[0].location.line)

    continuations: dict[BasicBlock, BasicBlock | None] = {}
    for cs_bb in callsub_bbs:
        last = cs_bb.assignments[-1].location
        # Heuristic 1: next BB in source order (excluding subroutine
        # entries — those are *targets*, not continuations).
        cont = None
        for b in bb_by_file_line.get(last.file, ()):
            if b.assignments[0].location.line <= last.line:
                continue
            if b in entries:
                continue
            cont = b
            break
        # Heuristic 2: retsub-targeted fallback.
        if cont is None:
            cs_target = callsub_target.get(cs_bb)
            if cs_target in bodies:
                candidates = [
                    c for c in retsub_targets_per_sub.get(cs_target, ())
                    if c.assignments
                    and c.assignments[0].location.file == last.file
                    and c.assignments[0].location.line > last.line
                ]
                if candidates:
                    cont = min(
                        candidates,
                        key=lambda c: c.assignments[0].location.line,
                    )
        continuations[cs_bb] = cont

    return {
        "entries": entries,
        "bodies": bodies,
        "continuations": continuations,
    }


def _compute_subroutine_summaries(
    prog: SSAProgram,
    entries: set[BasicBlock],
    bodies: dict[BasicBlock, set[BasicBlock]],
) -> dict[BasicBlock, tuple[int, int]]:
    """Per-subroutine ``(cost, submits)`` summary, computed by
    topo-sorting the call graph and folding bottom-up: each
    subroutine's cost is the sum of its body BBs' op costs, with
    each ``callsub`` op replaced by its callee's summary cost.

    Recursive call graphs degrade to a fixed-point iteration with
    a bounded number of rounds; the result remains a sound upper
    bound. Lazily imports ``opcode_cost`` from cost_analysis to
    avoid a hard cycle at module load time."""
    from .cost_analysis import opcode_cost

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
    """Sum body BB op costs, charging each ``callsub`` for its
    callee's static summary."""
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
    """Reduce an acyclic graph of regions to a single Region by
    repeatedly applying pattern matchers. Returns an
    :class:`ImproperR` wrapping whatever's left if no further
    reductions apply."""
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
        # Every node has a predecessor — pick any (irreducible loop
        # with no clear entry).
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
    """Sequence: ``n → m`` is the only edge out of ``n``, and the
    only edge into ``m``. Collapse to a ``SequenceR``."""
    if g.out_degree(n) != 1:
        return False
    m = next(iter(g.successors(n)))
    if m is n:
        return False
    if g.in_degree(m) != 1:
        return False
    seq = _flatten_sequence([n, m])
    _replace(g, [n, m], seq)
    return True


def _try_if_else(g: nx.DiGraph, n: Region) -> bool:
    """IfElse: ``n`` has 2 successors ``a, b``; each has only ``n``
    as predecessor and a single successor; both successors equal a
    common join. Collapse to an ``IfElseR``."""
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
    """IfThen: ``n`` has 2 successors ``a, b``; one of them
    (say ``a``) has only ``n`` as predecessor and its single
    successor is the *other* ``n``-successor ``b``. Collapse to
    an ``IfR`` with ``a`` as the then-arm; ``b`` becomes the
    join. Symmetric in which arm is the skip."""
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
    """Guard: peel off one **terminal** successor of ``n`` (out-degree
    0 in the residual graph, reached only from ``n``) into a
    ``GuardR``. ``n``'s remaining successors are preserved on the
    collapsed node.

    Generalised to any out-degree ≥ 2 — peeling one arm per iteration
    drives the residual towards an If/IfElse/Switch shape. Catches
    ABI dispatch chains, ``assert`` + ``err`` bailouts, and N-way
    branches where K of the arms early-exit."""
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
    """Switch: ``n`` has ≥3 successors, each a simple arm joining
    at a single common point. Collapse to a ``SwitchR``."""
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
    """``arm`` is reached only from ``head`` and has exactly one
    successor — eligible as an If/IfElse/Switch arm."""
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
    """Contract ``consumed`` (a head node + its companions) into ``new``.

    ``new`` inherits the predecessors of ``consumed[0]`` (minus the consumed
    set). Its successor is ``joins_to`` if given; otherwise ``new`` inherits
    the successors of ``consumed[-1]`` (also minus the consumed set) -- the
    "pair" case where the contraction has no explicit join target."""
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
    """Replace ``nodes`` with a single ``replacement``. External
    edges into any of ``nodes`` redirect to ``replacement``, and
    external out-edges originate from ``replacement``. Intra-cluster
    edges are dropped. Uses an ordered-dedup so edge insertion order
    is deterministic (sets keyed on identity-hashed Region objects
    would give run-to-run variance)."""
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


def to_dot(region: Region, *, nested: bool = True) -> str:
    """Render the control tree as a Graphviz DOT string.

    ``nested=True`` (default): each non-leaf region is a cluster
    (subgraph) containing its children — useful for *seeing* the
    decomposition. Leaf blocks show their op list. Sibling clusters
    don't carry CFG edges; ordering within a ``SequenceR`` is shown
    via dashed arrows so flow direction is visible.

    ``nested=False``: a pure parent-child tree where every region
    is its own node and edges are labelled by role (``"then"``,
    ``"body"``, ``"case 2"``, etc.). Easier to read for very
    deeply nested structures.

    Render with: ``dot -Tsvg tree.dot -o tree.svg`` or paste into
    https://dreampuf.github.io/GraphvizOnline.
    """
    if nested:
        return _to_dot_nested(region)
    return _to_dot_tree(region)


def _short_label(s: str) -> str:
    """Escape a string for use inside a Graphviz label."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _block_label(region: BlockR) -> str:
    # Escape each line's text individually, then join with literal
    # ``\l`` (Graphviz's left-align line break) — keep those unescaped
    # so they survive into the DOT output.
    parts = [
        _short_label(f"L{a.location.line:>3} {a.op}")
        for a in region.bb.assignments
    ]
    return "\\l".join(parts) + "\\l"


def _to_dot_nested(root: Region) -> str:
    """Nested-cluster rendering. Each non-leaf region is a cluster
    containing its children; the cluster's label shows the region
    kind. Sequences carry dashed-arrow ordering edges."""
    lines: list[str] = [
        "digraph ControlTree {",
        "  compound=true;",
        '  node [shape=box, fontname="monospace", fontsize=10];',
        '  edge [fontname="monospace", fontsize=9];',
        "  graph [labeljust=l, labelloc=t, style=rounded];",
    ]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def emit(region: Region, depth: int) -> tuple[str, str]:
        """Return ``(anchor_id, last_id)`` — the anchor we use for
        inter-cluster edges (the cluster name for non-leaves, the
        node id for leaves) and the same id again for symmetry."""
        pad = "  " * (depth + 1)
        if isinstance(region, BlockR):
            nid = fresh()
            lines.append(f'{pad}{nid} [label="{_block_label(region)}"];')
            return nid, nid
        cluster = f"cluster_{fresh()}"
        lines.append(f"{pad}subgraph {cluster} {{")
        kind_label = region.kind
        if isinstance(region, LoopR):
            kind_label = f"loop ({len(region.loop.nodes)} bbs, "
            kind_label += "reducible" if region.loop.is_reducible() else "irreducible"
            kind_label += ")"
        elif isinstance(region, ImproperR):
            kind_label = f"improper ({len(region.nodes)} nodes)"
        elif isinstance(region, SwitchR):
            kind_label = f"switch ({len(region.cases)} cases)"
        lines.append(f'{pad}  label="{kind_label}";')
        lines.append(f"{pad}  style=rounded;")
        lines.append(f"{pad}  color={_color_for(region)};")
        # Emit children and remember their anchors for intra-cluster wiring.
        anchors: list[str] = []
        for c in region.children():
            anchor, _ = emit(c, depth + 1)
            anchors.append(anchor)
        # Sequence: dashed-arrow chain through children.
        if isinstance(region, SequenceR) and len(anchors) >= 2:
            for a, b in zip(anchors, anchors[1:]):
                lines.append(f'{pad}  {a} -> {b} [style=dashed, arrowhead=open];')
        lines.append(f"{pad}}}")
        # Pick a stable representative inside the cluster so callers
        # wanting to draw an edge to the whole thing have a target.
        return anchors[0] if anchors else fresh(), cluster

    emit(root, 0)
    lines.append("}")
    return "\n".join(lines)


def _to_dot_tree(root: Region) -> str:
    """Parent-child rendering. Each region (including non-leaves) is
    its own node; edges are labelled by role."""
    lines: list[str] = [
        "digraph ControlTree {",
        "  rankdir=TB;",
        '  node [shape=box, fontname="monospace", fontsize=10];',
        '  edge [fontname="monospace", fontsize=9];',
    ]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def emit(region: Region) -> str:
        nid = fresh()
        color = _color_for(region)
        if isinstance(region, BlockR):
            lines.append(
                f'  {nid} [label="block\\l{_block_label(region)}", '
                f'color={color}];'
            )
            return nid
        # Non-leaf with summary label.
        if isinstance(region, SequenceR):
            label = f"sequence\\n({len(region.parts)} parts)"
        elif isinstance(region, LoopR):
            label = (
                f"loop\\n({len(region.loop.nodes)} bbs, "
                + ("reducible" if region.loop.is_reducible() else "irreducible")
                + ")"
            )
        elif isinstance(region, SwitchR):
            label = f"switch\\n({len(region.cases)} cases)"
        elif isinstance(region, ImproperR):
            label = f"improper\\n({len(region.nodes)} nodes)"
        else:
            label = region.kind
        lines.append(f'  {nid} [label="{label}", color={color}];')
        # Emit role-labelled child edges.
        if isinstance(region, SequenceR):
            for i, c in enumerate(region.parts):
                cid = emit(c)
                lines.append(f'  {nid} -> {cid} [label="{i}"];')
        elif isinstance(region, IfR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.then_branch)} [label="then"];')
        elif isinstance(region, IfElseR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.then_branch)} [label="then"];')
            lines.append(f'  {nid} -> {emit(region.else_branch)} [label="else"];')
        elif isinstance(region, GuardR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            lines.append(f'  {nid} -> {emit(region.exit_arm)} [label="exit"];')
        elif isinstance(region, SwitchR):
            lines.append(f'  {nid} -> {emit(region.cond)} [label="cond"];')
            for i, c in enumerate(region.cases):
                lines.append(f'  {nid} -> {emit(c)} [label="case {i}"];')
        elif isinstance(region, LoopR):
            lines.append(f'  {nid} -> {emit(region.body)} [label="body"];')
        elif isinstance(region, ImproperR):
            for i, c in enumerate(region.nodes):
                lines.append(f'  {nid} -> {emit(c)} [label="{i}"];')
        elif isinstance(region, ProgramR):
            for i, p in enumerate(region.programs):
                lines.append(f'  {nid} -> {emit(p)} [label="prog {i}"];')
        return nid

    emit(root)
    lines.append("}")
    return "\n".join(lines)


def _color_for(region: Region) -> str:
    """Per-kind border colour, makes the kinds easy to skim in DOT."""
    return {
        "block": "gray60",
        "sequence": "black",
        "if": "darkblue",
        "ifelse": "darkblue",
        "switch": "purple",
        "guard": "darkgreen",
        "loop": "darkorange",
        "improper": "red",
        "program": "navy",
    }.get(region.kind, "black")


def to_mermaid(region: Region) -> str:
    """Render the control tree as a Mermaid ``flowchart`` source —
    handy for inlining in markdown / Jupyter where Graphviz isn't
    available. Produces a parent-child tree mirroring
    :func:`_to_dot_tree`."""
    lines: list[str] = ["flowchart TD"]
    counter = [0]

    def fresh() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def safe(s: str) -> str:
        return s.replace('"', "'").replace("\n", "<br/>")

    def emit(region: Region) -> str:
        nid = fresh()
        if isinstance(region, BlockR):
            ops = "<br/>".join(
                f"L{a.location.line} {a.op}" for a in region.bb.assignments
            )
            lines.append(f'  {nid}["block<br/>{safe(ops)}"]')
            return nid
        if isinstance(region, SequenceR):
            lines.append(f'  {nid}(["sequence ({len(region.parts)} parts)"])')
            for i, c in enumerate(region.parts):
                lines.append(f"  {nid} -- {i} --> {emit(c)}")
        elif isinstance(region, IfR):
            lines.append(f'  {nid}{{"if"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- then --> {emit(region.then_branch)}")
        elif isinstance(region, IfElseR):
            lines.append(f'  {nid}{{"ifelse"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- then --> {emit(region.then_branch)}")
            lines.append(f"  {nid} -- else --> {emit(region.else_branch)}")
        elif isinstance(region, GuardR):
            lines.append(f'  {nid}{{"guard"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            lines.append(f"  {nid} -- exit --> {emit(region.exit_arm)}")
        elif isinstance(region, SwitchR):
            lines.append(f'  {nid}{{"switch ({len(region.cases)} cases)"}}')
            lines.append(f"  {nid} -- cond --> {emit(region.cond)}")
            for i, c in enumerate(region.cases):
                lines.append(f"  {nid} -- case{i} --> {emit(c)}")
        elif isinstance(region, LoopR):
            kind = "reducible" if region.loop.is_reducible() else "irreducible"
            lines.append(
                f'  {nid}[/"loop ({len(region.loop.nodes)} bbs, {kind})"\\]'
            )
            lines.append(f"  {nid} -- body --> {emit(region.body)}")
        elif isinstance(region, ImproperR):
            lines.append(f'  {nid}["improper ({len(region.nodes)} nodes)"]')
            for i, c in enumerate(region.nodes):
                lines.append(f"  {nid} -- {i} --> {emit(c)}")
        elif isinstance(region, ProgramR):
            lines.append(f'  {nid}[["programs ({len(region.programs)})"]]')
            for i, p in enumerate(region.programs):
                lines.append(f"  {nid} -- prog{i} --> {emit(p)}")
        return nid

    emit(region)
    return "\n".join(lines)


def pretty(region: Region, indent: int = 0) -> str:
    """Indented textual dump of the control tree. Useful for tests
    and debug."""
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
