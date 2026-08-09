"""Budget-feasibility queries for blocks and individual assignments."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

import networkx as nx

from ..cfg import CFG
from ..ssa import Assignment, BasicBlock, SSAProgram
from .context import BudgetContext, context_for
from .costs import CostFact, assignment_cost, block_cost, canonical_assignments, sum_costs


BudgetTarget = Union[BasicBlock, Assignment]


@dataclass(frozen=True)
class MinimumCost:
    target: BudgetTarget
    cost: Optional[CostFact]
    path: tuple[BasicBlock, ...]
    context: BudgetContext
    degradations: tuple[str, ...] = ()

    @property
    def reachable(self) -> bool:
        return self.cost is not None

    @property
    def proven_over_budget(self) -> bool:
        """Every CFG execution reaching the target spends too much.

        This uses a lower cost bound, so dynamic opcode costs do not invalidate
        the proof.  The raw CFG may admit mismatched return paths; those only
        make the minimum smaller and therefore make this proof harder, never
        easier.
        """
        return self.cost is not None and self.cost.lower > self.context.initial_credit

    @property
    def has_within_budget_path(self) -> bool:
        """The selected structural path has a finite upper cost within credit."""
        return (
            self.cost is not None
            and self.cost.upper is not None
            and self.cost.upper <= self.context.initial_credit
        )

    @property
    def verdict(self) -> str:
        if not self.reachable:
            return "unreachable"
        if self.proven_over_budget:
            return "budget-infeasible"
        if self.has_within_budget_path:
            return "within-budget structural path"
        return "unknown"


def _target_block(target: BudgetTarget) -> BasicBlock:
    if isinstance(target, BasicBlock):
        return target
    if target.basic_block is None:
        raise ValueError("assignment is not attached to a basic block")
    return target.basic_block


def _target_block_cost(target: BudgetTarget) -> CostFact:
    block = _target_block(target)
    if isinstance(target, BasicBlock):
        return block_cost(block)
    facts = []
    found = False
    for assignment in canonical_assignments(block):
        facts.append(assignment_cost(assignment))
        if assignment is target or (
            assignment.location == target.location
            and assignment.op == target.op
            and assignment.immediates == target.immediates
        ):
            found = True
            break
    if not found:
        raise ValueError("assignment is not in its block's canonical stream")
    return sum_costs(facts)


def _weighted_cfg(cfg: CFG) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(cfg.blocks)
    for block in cfg.blocks:
        for successor in block.successors:
            graph.add_edge(block, successor, weight=block_cost(successor).lower)
    return graph


def minimum_cost(
    prog: SSAProgram,
    target: BudgetTarget,
    cfg: Optional[CFG] = None,
    *,
    context: Optional[BudgetContext] = None,
) -> MinimumCost:
    """Minimum structural cost required to execute ``target``.

    The path search deliberately uses the over-approximating raw CFG.  A
    context-insensitive return can create an impossible cheaper path, but can
    never create the false claim that every path exceeds budget.
    """
    cfg = cfg or CFG.of(prog)
    ctx = context_for(prog, context)
    target_block = _target_block(target)
    graph = _weighted_cfg(cfg)
    chosen: Optional[list[BasicBlock]] = None
    chosen_lower: Optional[int] = None
    for entry in cfg.entries:
        try:
            path = nx.shortest_path(graph, entry, target_block, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        lower = sum(block_cost(block).lower for block in path[:-1])
        lower += _target_block_cost(target).lower
        if chosen_lower is None or lower < chosen_lower:
            chosen, chosen_lower = path, lower
    if chosen is None:
        return MinimumCost(target, None, (), ctx)

    cost = sum_costs(block_cost(block) for block in chosen[:-1]) + _target_block_cost(target)
    returns = [block for block in chosen if any(
        assignment.op == "retsub" for assignment in canonical_assignments(block)
    )]
    degradations = list(cost.reasons)
    if returns:
        degradations.append("raw CFG path may pair a return with the wrong caller")
    return MinimumCost(
        target,
        cost,
        tuple(chosen),
        ctx,
        tuple(dict.fromkeys(degradations)),
    )


def minimum_costs(
    prog: SSAProgram,
    cfg: Optional[CFG] = None,
    *,
    context: Optional[BudgetContext] = None,
) -> dict[BasicBlock, MinimumCost]:
    """Minimum cost to every block, sharing a public result shape."""
    cfg = cfg or CFG.of(prog)
    ctx = context_for(prog, context)
    return {
        block: minimum_cost(prog, block, cfg, context=ctx)
        for block in cfg.blocks
    }
