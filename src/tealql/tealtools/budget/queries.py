"""Budget-feasibility queries for blocks and individual assignments."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

import networkx as nx

from ..cfg import CFG
from ..ssa import Assignment, BasicBlock, SSAProgram
from .context import BudgetContext, context_for
from .costs import CostFact, CostModel, canonical_assignments, sum_costs


BudgetTarget = Union[BasicBlock, Assignment]


@dataclass(frozen=True)
class MinimumCost:
    target: BudgetTarget
    cost: Optional[CostFact]
    path: tuple[BasicBlock, ...]
    context: BudgetContext
    degradations: tuple[str, ...] = ()
    within_budget_path: tuple[BasicBlock, ...] = ()
    within_budget_cost: Optional[CostFact] = None

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
        """Some structural path has a finite upper cost within credit."""
        return (
            self.within_budget_cost is not None
            and self.within_budget_cost.upper is not None
            and self.within_budget_cost.upper <= self.context.initial_credit
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


def _target_block_cost(target: BudgetTarget, model: CostModel) -> CostFact:
    block = _target_block(target)
    if isinstance(target, BasicBlock):
        return model.execution_block_cost(block)
    facts = []
    found = False
    for assignment in canonical_assignments(block):
        facts.append(model.assignment_cost(assignment))
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


def _weighted_cfg(cfg: CFG, model: CostModel, pp, *, upper: bool) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(cfg.blocks)
    subroutines = model._subroutine_info()
    for block in cfg.blocks:
        for successor in block.successors:
            if not pp.edge_is_feasible(block, successor):
                continue
            # Distances are to block ENTRY.  Charge the source block on its
            # outgoing edge so a target assignment can use only its in-block
            # prefix; a dynamic operation later in that block must not erase a
            # finite witness to an earlier assignment.
            fact = model.block_cost(block)
            weight = fact.upper if upper else fact.lower
            if weight is not None:
                graph.add_edge(block, successor, weight=weight)
        # A context-correct returning path can summarize a call directly to its
        # matched continuation.  Keep the raw call-target edge above as well so
        # queries for sites inside the callee remain reachable.  Crucially, only
        # this synthetic edge charges the callee summary; charging it on the raw
        # edge would count the callee once here and again while traversing it.
        if model._terminator(block) == "callsub":
            continuation = subroutines["continuations"].get(block)
            if continuation is not None:
                fact = model.execution_block_cost(block)
                weight = fact.upper if upper else fact.lower
                if weight is not None:
                    existing = graph.get_edge_data(block, continuation)
                    if existing is None or weight < existing["weight"]:
                        graph.add_edge(block, continuation, weight=weight)
    return graph


def _all_distances(cfg: CFG, model: CostModel, pp, *, upper: bool):
    """Cheapest paths to every block from a synthetic multi-entry source."""
    graph = _weighted_cfg(cfg, model, pp, upper=upper)
    source = object()
    graph.add_node(source)
    for entry in cfg.entries:
        graph.add_edge(source, entry, weight=0)
    distances, paths = nx.single_source_dijkstra(graph, source, weight="weight")
    return (
        {block: distance for block, distance in distances.items() if block is not source},
        {
            block: tuple(node for node in path if node is not source)
            for block, path in paths.items() if block is not source
        },
    )


def _path_cost(
    path: tuple[BasicBlock, ...], target: BudgetTarget, model: CostModel,
    *, upper: bool,
) -> CostFact:
    """Total charge of the witness ``path`` plus the target's own prefix.

    HAZARD: mirror :func:`_weighted_cfg` EDGE BY EDGE. Charging
    ``execution_block_cost`` on every prefix block counts a callee TWICE when
    the path walks the raw ``callsub``→entry edge (the summary on the call
    block plus the callee's own blocks) — which produced a wrong
    "budget-infeasible" PROOF at a truly affordable in-callee target."""
    if not path:
        raise ValueError("a cost witness path must not be empty")
    subroutines = model._subroutine_info()

    def bound(fact: CostFact):
        return fact.upper if upper else fact.lower

    charges = []
    for block, nxt in zip(path, path[1:]):
        plain = model.block_cost(block)
        if (model._terminator(block) == "callsub"
                and subroutines["continuations"].get(block) is nxt):
            summarized = model.execution_block_cost(block)
            if nxt in block.successors:
                # Both edges existed; the search took the lighter one at
                # THIS bound — charge the same.
                b_p, b_s = bound(plain), bound(summarized)
                charges.append(
                    plain if b_p is not None and (b_s is None or b_p <= b_s)
                    else summarized)
            else:
                charges.append(summarized)
        else:
            charges.append(plain)
    return sum_costs(charges) + _target_block_cost(target, model)


def _minimum_cost_from_maps(
    target: BudgetTarget,
    ctx: BudgetContext,
    model: CostModel,
    lower_paths,
    upper_paths,
) -> MinimumCost:
    target_block = _target_block(target)
    lower_block_path = lower_paths.get(target_block)
    if lower_block_path is None:
        return MinimumCost(target, None, (), ctx)
    lower_cost = _path_cost(lower_block_path, target, model, upper=False)

    upper_block_path = upper_paths.get(target_block)
    upper_cost = (
        _path_cost(upper_block_path, target, model, upper=True)
        if upper_block_path is not None else None
    )
    # An assignment target may occur before an unbounded operation later in
    # its block, so recompute its prefix before accepting the upper witness.
    if upper_cost is not None and upper_cost.upper is None:
        upper_block_path, upper_cost = (), None

    degradations = list(lower_cost.reasons)
    if any(
        any(assignment.op == "retsub" for assignment in canonical_assignments(block))
        for block in lower_block_path
    ):
        degradations.append("raw CFG path may pair a return with the wrong caller")
    return MinimumCost(
        target,
        lower_cost,
        lower_block_path,
        ctx,
        tuple(dict.fromkeys(degradations)),
        upper_block_path or (),
        upper_cost,
    )


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
    model = CostModel(prog, avm_version=ctx.avm_version)
    from ..cfg.path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(prog)
    _lower_distances, lower_paths = _all_distances(
        cfg, model, pp, upper=False
    )
    _upper_distances, upper_paths = _all_distances(
        cfg, model, pp, upper=True
    )
    return _minimum_cost_from_maps(
        target, ctx, model, lower_paths, upper_paths
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
    model = CostModel(prog, avm_version=ctx.avm_version)
    from ..cfg.path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(prog)
    _lower_distances, lower_paths = _all_distances(
        cfg, model, pp, upper=False
    )
    _upper_distances, upper_paths = _all_distances(
        cfg, model, pp, upper=True
    )
    return {
        block: _minimum_cost_from_maps(
            block, ctx, model, lower_paths, upper_paths
        )
        for block in cfg.blocks
    }
