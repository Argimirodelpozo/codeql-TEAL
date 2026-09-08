"""Reachable loop regions with cost and independently proved stack bounds."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

import networkx as nx

from .._utils.dot import (
    bb_label as _bb_label,
    escape,
    header as _dot_header,
    render as _dot_render,
)
from ..cfg import CFG
from ..cfg.loops import _LoopShape, _routine_graph, _loop_shapes
from ..ssa import BasicBlock, SSAProgram
from .context import BudgetContext, MAX_STACK_DEPTH, context_for
from .costs import (
    CostModel,
    CostFact,
    block_cost,
    block_stack_delta,
    sum_costs,
)


# The one canonical control-op spelling lives beside the cost model.
from .costs import terminator_op as _terminator


@dataclass(frozen=True)
class LoopBound:
    """One reachable cyclic region.

    Budget bounds use the cheapest possible cycle cost.  Stack bounds are
    present only when *every* relevant simple cycle was exhaustively checked
    and proved to grow the stack.  The two proofs are intentionally separate.
    """

    kind: str                         # reducible | irreducible
    header: BasicBlock
    entries: tuple[BasicBlock, ...]
    body: frozenset[BasicBlock]
    back_edges: tuple[tuple[BasicBlock, BasicBlock], ...]
    iteration_cost: CostFact
    prefix: CostFact
    budget_bound: int
    stack_growth: Optional[int]
    stack_bound: Optional[int]
    context: BudgetContext
    degradations: tuple[str, ...] = ()
    depth: int = 0
    semantic_trip_bound: Optional[int] = None
    semantic_reason: str = ''

    @property
    def min_iteration_cost(self) -> int:
        return self.iteration_cost.lower

    @property
    def prefix_cost(self) -> int:
        return self.prefix.lower

    @property
    def stack_delta(self) -> int:
        return self.stack_growth or 0

    @property
    def budget(self) -> int:
        return self.context.initial_credit

    @property
    def available_budget(self) -> int:
        return max(0, self.context.initial_credit - self.prefix.lower)

    @property
    def max_iterations(self) -> int:
        if self.stack_bound is None:
            return self.budget_bound
        return min(self.budget_bound, self.stack_bound)

    @property
    def bound_reason(self) -> str:
        if self.stack_bound is not None and self.stack_bound < self.budget_bound:
            return "stack"
        return "budget"

    @property
    def exact_cost(self) -> bool:
        return self.iteration_cost.exact and self.prefix.exact

    @property
    def first_line(self) -> int:
        return self.header.first_line


def _path_cost(
    path: list[BasicBlock],
    model: CostModel,
    *,
    summarize_calls: bool,
) -> CostFact:
    cost_of = model.execution_block_cost if summarize_calls else model.block_cost
    return sum_costs(cost_of(bb) for bb in path)


def _cheapest_path(
    graph: nx.DiGraph, source: BasicBlock, target: BasicBlock, model: CostModel,
) -> Optional[list[BasicBlock]]:
    weighted = nx.DiGraph()
    weighted.add_nodes_from(graph.nodes)
    for u, v in graph.edges:
        weighted.add_edge(u, v, weight=model.execution_block_cost(v).lower)
    try:
        return nx.shortest_path(weighted, source, target, weight="weight")
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def _cheapest_iteration(
    shape: _LoopShape, graph: nx.DiGraph, model: CostModel,
) -> CostFact:
    if shape.kind == "reducible":
        best: Optional[CostFact] = None
        for source, target in shape.back_edges:
            if target is not shape.header:
                continue
            path = _cheapest_path(
                graph.subgraph(shape.body), shape.header, source, model
            )
            if path is None:
                continue
            fact = _path_cost(path, model, summarize_calls=True)
            if best is None or fact.lower < best.lower:
                best = fact
        return best or _path_cost([shape.header], model, summarize_calls=True)

    subgraph = graph.subgraph(shape.body)
    best = None
    for u, v in subgraph.edges:
        if u is v:
            path = [u]
        else:
            tail = _cheapest_path(subgraph, v, u, model)
            if tail is None:
                continue
            path = tail
        fact = _path_cost(path, model, summarize_calls=True)
        if best is None or fact.lower < best.lower:
            best = fact
    return best or CostFact.unknown("cyclic SCC had no materialized cycle")


def _entry_distances(
    cfg: CFG, model: CostModel, pp=None,
) -> tuple[dict[BasicBlock, int], dict[BasicBlock, list[BasicBlock]]]:
    """Cheapest raw-CFG paths.

    Raw return edges may admit an impossible caller pairing, which can only
    lower the result.  That is the conservative direction for the lower-bound
    fact returned here and is explicitly surfaced by query health.
    """
    graph = nx.DiGraph()
    graph.add_nodes_from(cfg.blocks)
    for bb in cfg.blocks:
        for successor in bb.successors:
            if pp is not None and not pp.edge_is_feasible(bb, successor):
                continue
            graph.add_edge(bb, successor, weight=model.block_cost(successor).lower)
    distances: dict[BasicBlock, int] = {}
    paths: dict[BasicBlock, list[BasicBlock]] = {}
    for entry in cfg.entries:
        if entry not in graph:
            continue
        lengths, found_paths = nx.single_source_dijkstra(graph, entry, weight="weight")
        base = model.block_cost(entry).lower
        for node, distance in lengths.items():
            total = base + distance
            if node not in distances or total < distances[node]:
                distances[node] = total
                paths[node] = found_paths[node]
    return distances, paths


def _prefix(
    shape: _LoopShape, distances: dict, paths: dict, model: CostModel,
) -> CostFact:
    candidates = [entry for entry in shape.entries if entry in distances]
    if not candidates:
        return CostFact.unknown("loop region has no reachable entry", lower=0)
    target = min(candidates, key=distances.__getitem__)
    path = paths[target]
    # The entry block belongs to an iteration, not the mandatory prefix.
    return (
        _path_cost(path[:-1], model, summarize_calls=False)
        if len(path) > 1 else CostFact.known(0)
    )


def _guaranteed_stack_growth(
    shape: _LoopShape, graph: nx.DiGraph, *, max_cycles: int = 4096
) -> tuple[Optional[int], Optional[str]]:
    subgraph = graph.subgraph(shape.body)
    if len(shape.body) > 64:
        return None, "stack proof skipped for a region above 64 blocks"
    deltas = {bb: block_stack_delta(bb) for bb in shape.body}
    if any(delta is None for delta in deltas.values()):
        return None, "stack proof unavailable across call/return boundaries"

    minimum: Optional[int] = None
    seen = 0
    for cycle in nx.simple_cycles(subgraph):
        seen += 1
        if seen > max_cycles:
            return None, f"stack proof exceeded {max_cycles} simple cycles"
        growth = sum(deltas[bb] for bb in cycle)  # type: ignore[arg-type]
        # A nested cycle can repeat between two header visits.  Zero growth can
        # avoid the claimed growth entirely; negative growth can offset pushes
        # on the outer lap.  Either voids an outer stack ceiling even though the
        # nested cycle itself does not contain the outer header.
        if growth <= 0:
            return None, None
        if shape.kind == "reducible" and shape.header not in cycle:
            continue
        minimum = growth if minimum is None else min(minimum, growth)
    if minimum is None:
        return None, "no relevant simple cycle was materialized"
    return minimum, None


def analyze_loops(
    prog: SSAProgram,
    cfg: Optional[CFG] = None,
    *,
    context: Optional[BudgetContext] = None,
    budget: Optional[int] = None,
) -> list[LoopBound]:
    """Return all reachable reducible loops and irreducible cyclic regions."""
    from ..analysis import FactDomain
    induction = prog.facts(FactDomain.RANGES).loop_analysis()
    cfg = cfg or induction.cfg
    ctx = context_for(prog, context, budget=budget)
    model = CostModel(prog, avm_version=ctx.avm_version)
    pp = induction.base.predicates
    graph, roots = ((induction.graph, induction.roots) if cfg is induction.cfg
                    else _routine_graph(prog, cfg, pp))
    distances, paths = _entry_distances(cfg, model, pp)
    out: list[LoopBound] = []
    for shape in _loop_shapes(graph, roots):
        iteration = _cheapest_iteration(shape, graph, model)
        prefix = _prefix(shape, distances, paths, model)
        available = max(0, ctx.initial_credit - prefix.lower)
        cost_floor = max(1, iteration.lower)
        growth, stack_degradation = _guaranteed_stack_growth(shape, graph)
        stack_bound = MAX_STACK_DEPTH // growth if growth is not None else None
        proof = induction.summary(shape)
        degradations = tuple(dict.fromkeys((
            *iteration.reasons,
            *prefix.reasons,
            *((stack_degradation,) if stack_degradation else ()),
            *(("context-insensitive prefix return edges",)
              if any(_terminator(bb) == "retsub" for bb in paths.get(shape.header, ()))
              else ()),
        )))
        out.append(LoopBound(
            shape.kind,
            shape.header,
            shape.entries,
            shape.body,
            shape.back_edges,
            iteration,
            prefix,
            available // cost_floor,
            growth,
            stack_bound,
            ctx,
            degradations,
            semantic_trip_bound=proof.trip_bound,
            semantic_reason=proof.reason,
        ))

    nested = [
        replace(loop, depth=sum(
            1 for other in out if other is not loop and loop.body < other.body
        ))
        for loop in out
    ]
    return sorted(nested, key=lambda item: (
        item.header.file, item.header.first_line, item.kind
    ))


def render(
    prog: SSAProgram,
    cfg: Optional[CFG] = None,
    *,
    context: Optional[BudgetContext] = None,
) -> str:
    loops = analyze_loops(prog, cfg, context=context)
    if not loops:
        return "no reachable loops"
    rows = ["loops (execution ceilings, not predicted trip counts):"]
    for loop in loops:
        precision = "exact cost" if loop.exact_cost else "lower-bound cost"
        entry = (f", {len(loop.entries)} entries" if len(loop.entries) > 1 else "")
        stack = (
            f", guaranteed stack growth +{loop.stack_growth}"
            if loop.stack_growth is not None else ""
        )
        rows.append(
            "  " + "  " * loop.depth
            + f"L{loop.header.first_line}: {loop.kind}{entry}, "
            + f">={loop.iteration_cost.lower}/cycle ({precision}), "
            + f">={loop.prefix.lower} prefix{stack} -> "
            + f"at most {loop.max_iterations} ({loop.bound_reason})"
            + (f", semantic trip cap {loop.semantic_trip_bound}"
               if loop.semantic_trip_bound is not None else ", semantic trip cap unknown")
        )
        for reason in loop.degradations:
            rows.append("  " + "  " * (loop.depth + 1) + f"~ {reason}")
    return "\n".join(rows)


def to_dot(
    prog: SSAProgram,
    cfg: Optional[CFG] = None,
    *,
    file: Optional[str] = None,
    rankdir: str = "TB",
    context: Optional[BudgetContext] = None,
) -> str:
    cfg = cfg or CFG.of(prog)
    loops = analyze_loops(prog, cfg, context=context)
    blocks = [bb for bb in cfg.blocks if file is None or bb.file == file]
    shown = set(blocks)
    owner: dict[BasicBlock, LoopBound] = {}
    for loop in sorted(loops, key=lambda item: -len(item.body)):
        for bb in loop.body:
            owner[bb] = loop
    marked_edges = {edge for loop in loops for edge in loop.back_edges}

    def node_id(bb: BasicBlock) -> str:
        return f"bb_{bb.first_line}_{bb.last_line}"

    def node_line(bb: BasicBlock) -> str:
        fact = block_cost(bb)
        suffix = "" if fact.exact else "+"
        label = _bb_label(
            f"L{bb.first_line}-L{bb.last_line}", [f"{fact.lower}{suffix} budget"]
        )
        style = (
            'style="filled,bold", fillcolor="#dbe9ff", color="#1f5fa8"'
            if any(bb in loop.entries for loop in loops)
            else 'style="filled", fillcolor="#f6f6f6", color="#999999"'
        )
        return f'    {node_id(bb)} [shape=box, label="{label}", {style}];'

    out = _dot_header("loop_bounds", rankdir=rankdir)
    index = {loop: i for i, loop in enumerate(loops)}
    children: dict[Optional[LoopBound], list[LoopBound]] = {None: []}
    for loop in loops:
        parents = [other for other in loops if loop.body < other.body]
        parent = min(parents, key=lambda item: len(item.body)) if parents else None
        children.setdefault(parent, []).append(loop)
        children.setdefault(loop, [])

    def emit(loop: LoopBound, indent: str) -> None:
        quality = "exact" if loop.iteration_cost.exact else "lower"
        label = (
            f"{loop.kind} L{loop.header.first_line}: <= {loop.max_iterations} iter, "
            f"{loop.iteration_cost.lower}/iter ({quality})"
        )
        out.append(f"{indent}subgraph cluster_{index[loop]} {{")
        out.append(f'{indent}  label="{escape(label)}"; color="#1f5fa8"; style=rounded;')
        for child in children.get(loop, ()):
            emit(child, indent + "  ")
        for bb in blocks:
            if owner.get(bb) is loop:
                out.append(node_line(bb))
        out.append(indent + "}")

    for root in children[None]:
        emit(root, "  ")
    for bb in blocks:
        if bb not in owner:
            out.append(node_line(bb))
    for bb in blocks:
        for successor in bb.successors:
            if successor not in shown:
                continue
            attrs = (
                '[color="#c0392b", style=bold, label="cycle"]'
                if (bb, successor) in marked_edges else ""
            )
            out.append(f"  {node_id(bb)} -> {node_id(successor)} {attrs};")
    out.append("}")
    return "\n".join(out)


def draw(
    prog: SSAProgram,
    cfg: Optional[CFG] = None,
    *,
    file: Optional[str] = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
    context: Optional[BudgetContext] = None,
):
    return _dot_render(
        to_dot(prog, cfg, file=file, rankdir=rankdir, context=context),
        format=format,
        engine=engine,
    )
