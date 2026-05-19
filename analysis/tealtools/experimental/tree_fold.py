"""Generic recursive fold over a control tree.

Subclass :class:`TreeFold` with a per-analysis state type ``T`` and
override:

- :meth:`initial` — starting state at program entry.
- :meth:`merge` — combine multiple states at a join point.
- :meth:`visit_op` — per-op state transition (typically where per-line
  recording happens).
- :meth:`visit_loop` — by default folds the body once; override for
  budget-style analyses that need to iterate to a cap.

Every other region kind (``Sequence`` / ``If`` / ``IfElse`` /
``Switch`` / ``Guard`` / ``Improper`` / ``Program`` / ``Subroutine``)
has a sensible default in this class — you only override the ones
your analysis needs.

The :meth:`visit_program` default folds main programs and subroutines
each from :meth:`initial` (intraprocedurally). For interprocedural
analyses that want to compose subroutine summaries at ``callsub``
sites, override :meth:`visit_op` to do the summary lookup.
"""
from __future__ import annotations

from typing import Generic, Optional, TypeVar

import networkx as nx

from ..control_tree import (
    BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR,
    ImproperR, ProgramR, SubroutineR, Region, build_control_tree,
)
from ..ssa import SSAProgram

T = TypeVar("T")


class TreeFold(Generic[T]):
    """Base class. Subclass and override the bits your analysis needs."""

    def __init__(self, prog: SSAProgram):
        self.prog = prog
        self.tree: Region = build_control_tree(prog)
        # If multi-program, expose the subroutine summaries — analyses
        # that want them (e.g. interprocedural cost) can look them up.
        if isinstance(self.tree, ProgramR):
            self.subroutine_summaries: dict = self.tree.subroutine_summaries
            self.subroutines: dict[Region, Region] = self.tree.subroutines
        else:
            self.subroutine_summaries = {}
            self.subroutines = {}

    # --- subclass API --------------------------------------------------

    def initial(self) -> T:
        raise NotImplementedError

    def merge(self, states: list[T]) -> T:
        raise NotImplementedError

    def visit_op(self, op, state: T, bb=None) -> T:
        """Per-op state transition. ``op`` is an :class:`Assignment`
        from ``BlockR.bb.assignments``; ``bb`` is its containing
        :class:`BasicBlock` (handy for analyses that need to look at
        successor edges, e.g. resolving ``callsub`` targets).
        Default: pass-through."""
        return state

    # --- region defaults (override as needed) --------------------------

    def visit_block(self, region: BlockR, state: T) -> T:
        for a in region.bb.assignments:
            state = self.visit_op(a, state, region.bb)
        return state

    def visit_sequence(self, region: SequenceR, state: T) -> T:
        for part in region.parts:
            state = self.visit(part, state)
        return state

    def visit_if(self, region: IfR, state: T) -> T:
        cond_s = self.visit(region.cond, state)
        then_s = self.visit(region.then_branch, cond_s)
        return self.merge([cond_s, then_s])

    def visit_ifelse(self, region: IfElseR, state: T) -> T:
        cond_s = self.visit(region.cond, state)
        then_s = self.visit(region.then_branch, cond_s)
        else_s = self.visit(region.else_branch, cond_s)
        return self.merge([then_s, else_s])

    def visit_switch(self, region: SwitchR, state: T) -> T:
        cond_s = self.visit(region.cond, state)
        arm_states = [self.visit(case, cond_s) for case in region.cases]
        return self.merge([cond_s] + arm_states) if arm_states else cond_s

    def visit_guard(self, region: GuardR, state: T) -> T:
        cond_s = self.visit(region.cond, state)
        # Exit arm runs but doesn't continue forward; visit for recording.
        self.visit(region.exit_arm, cond_s)
        return cond_s

    def visit_loop(self, region: LoopR, state: T) -> T:
        """Default: single body pass. Override for budget-style
        analyses that need to iterate to a cap (cost, itxn-count)."""
        return self.visit(region.body, state)

    def visit_improper(self, region: ImproperR, state: T) -> T:
        """Acyclic-DAG fold (loops were collapsed in Phase 1 of
        :func:`build_control_tree`, so the residual is a DAG by
        construction). Threads state through topological order,
        merging at each join."""
        g = nx.DiGraph()
        for n in region.nodes:
            g.add_node(n)
        for u, v in region.edges:
            g.add_edge(u, v)
        try:
            topo = list(nx.topological_sort(g))
        except nx.NetworkXUnfeasible:
            # Cyclic improper — degenerate, fall back to merge-all.
            return self.merge(
                [self.visit(n, state) for n in region.nodes] or [state]
            )
        entry_ids = {id(e) for e in region.entries}
        in_state: dict[int, Optional[T]] = {id(n): None for n in region.nodes}
        for n in region.nodes:
            if id(n) in entry_ids:
                in_state[id(n)] = state
        sink_exits: list[T] = []
        for n in topo:
            s = in_state[id(n)]
            if s is None:
                continue
            exit_s = self.visit(n, s)
            succs = list(g.successors(n))
            if not succs:
                sink_exits.append(exit_s)
                continue
            for sc in succs:
                prev = in_state[id(sc)]
                in_state[id(sc)] = (
                    exit_s if prev is None else self.merge([prev, exit_s])
                )
        return self.merge(sink_exits) if sink_exits else state

    def visit_program(self, region: ProgramR, state: T) -> T:
        """Fold each independent program and subroutine from a fresh
        :meth:`initial` state. The aggregated ``state`` returned here
        isn't meaningful for analyses that want per-program output —
        check per-line records (the analysis is responsible for its
        own bookkeeping in :meth:`visit_op`)."""
        for p in region.programs:
            self.visit(p, self.initial())
        for sub in region.subroutines.values():
            self.visit(sub, self.initial())
        return state

    def visit_subroutine(self, region: SubroutineR, state: T) -> T:
        return self.visit(region.body, state)

    # --- dispatch ------------------------------------------------------

    def visit(self, region: Region, state: T) -> T:
        method = getattr(self, f"visit_{region.kind}", None)
        if method is None:
            return state
        return method(region, state)

    def run(self) -> T:
        return self.visit(self.tree, self.initial())
