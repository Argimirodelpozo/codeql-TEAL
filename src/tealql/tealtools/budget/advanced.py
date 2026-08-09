"""Higher-level resource queries built on cost and loop facts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from ..analysis import FactDomain
from ..cfg import CFG
from ..ssa import Assignment, BasicBlock, Const, Phi, SSAProgram, SSAVar, binary_operands, const_int
from ..structure import analyze_structure
from .context import BudgetContext, context_for
from .costs import CostFact, assignment_cost, block_cost, canonical_assignments, sum_costs
from .loop_bounds import LoopBound, analyze_loops
from .queries import MinimumCost, minimum_cost


@dataclass(frozen=True)
class MethodBudgetSummary:
    name: str
    blocks: frozenset[BasicBlock]
    exits: tuple[Assignment, ...]
    approving_exits: tuple[Assignment, ...]
    minimum_exit: Optional[MinimumCost]
    loops: tuple[LoopBound, ...]
    context: BudgetContext

    @property
    def minimum_required(self) -> Optional[CostFact]:
        return None if self.minimum_exit is None else self.minimum_exit.cost

    @property
    def proven_infeasible(self) -> bool:
        return bool(self.minimum_exit and self.minimum_exit.proven_over_budget)


def summarize_methods(
    prog: SSAProgram,
    *,
    context: Optional[BudgetContext] = None,
) -> list[MethodBudgetSummary]:
    """Minimum entry-to-exit cost and loop regions for each handler component."""
    ctx = context_for(prog, context)
    structure = analyze_structure(prog)
    loops = analyze_loops(prog, context=ctx)
    from ..cfg.exits import is_approval_exit
    out: list[MethodBudgetSummary] = []
    for name, blocks in structure.handler_functions():
        exits = tuple(
            assignment
            for block in blocks
            for assignment in canonical_assignments(block)
            if assignment.op in {"return", "err"}
        )
        approving = tuple(
            assignment
            for assignment in exits
            if assignment.op == "return"
            and assignment.basic_block is not None
            and is_approval_exit(assignment.basic_block)
        )
        results = [
            minimum_cost(prog, exit_assignment, context=ctx)
            for exit_assignment in approving
        ]
        reachable = [result for result in results if result.cost is not None]
        cheapest = min(reachable, key=lambda result: result.cost.lower) if reachable else None
        out.append(MethodBudgetSummary(
            name,
            blocks,
            exits,
            approving,
            cheapest,
            tuple(loop for loop in loops if loop.body <= blocks),
            ctx,
        ))
    return out


@dataclass(frozen=True)
class OpcodeBudgetGuard:
    read: Assignment
    enforcement: Assignment
    relation: str
    threshold: int
    guaranteed_credit: int
    downstream_lower: Optional[int]
    downstream_upper: Optional[int]
    verdict: str
    reasons: tuple[str, ...] = ()

    @property
    def sufficient(self) -> bool:
        return self.verdict == "sufficient"


_FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _budget_read(value, facts) -> Optional[Assignment]:
    value = facts.resolve(value)
    if not isinstance(value, SSAVar):
        return None
    definition = value.defined_by
    if (definition is not None and definition.op == "global"
            and definition.immediates.strip() == "OpcodeBudget"):
        return definition
    return None


def _constant_int(value, facts) -> Optional[int]:
    constant = facts.constant(value)
    return const_int(constant if constant is not None else value)


def _guard_shape(assertion: Assignment, facts):
    if assertion.op != "assert" or not assertion.inputs:
        return None
    condition = facts.resolve(assertion.inputs[0])
    comparison = getattr(condition, "defined_by", None)
    if comparison is None or comparison.op not in _FLIP or len(comparison.inputs) != 2:
        return None
    lhs, rhs = binary_operands(comparison)
    lhs_read, rhs_read = _budget_read(lhs, facts), _budget_read(rhs, facts)
    if lhs_read is not None:
        threshold = _constant_int(rhs, facts)
        return None if threshold is None else (lhs_read, comparison.op, threshold)
    if rhs_read is not None:
        threshold = _constant_int(lhs, facts)
        return None if threshold is None else (rhs_read, _FLIP[comparison.op], threshold)
    return None


def _reachable_graph(cfg: CFG, starts) -> nx.DiGraph:
    graph = nx.DiGraph()
    work = list(starts)
    seen = set(work)
    while work:
        block = work.pop()
        graph.add_node(block)
        for successor in block.successors:
            graph.add_edge(block, successor)
            if successor not in seen:
                seen.add(successor)
                work.append(successor)
    return graph


def _suffix_cost_bounds(read: Assignment, enforcement: Assignment, cfg: CFG):
    block = read.basic_block
    if block is None or enforcement.basic_block is not block:
        return None, None, ("budget read and enforcement are in different blocks",)
    stream = canonical_assignments(block)
    try:
        read_index = next(i for i, assignment in enumerate(stream) if assignment is read)
    except StopIteration:
        return None, None, ("budget read is absent from canonical stream",)
    suffix = sum_costs(assignment_cost(assignment) for assignment in stream[read_index + 1:])
    reasons = list(suffix.reasons)
    if not block.successors:
        return suffix.lower, suffix.upper, tuple(reasons)

    graph = _reachable_graph(cfg, block.successors)
    if not nx.is_directed_acyclic_graph(graph):
        reasons.append("a reachable cycle makes downstream upper cost unbounded")
        upper = None
    elif any(block_cost(node).upper is None for node in graph.nodes):
        reasons.append("dynamic opcode cost has no finite downstream upper bound")
        upper = None
    else:
        upper_dp: dict[BasicBlock, int] = {}
        for node in reversed(list(nx.topological_sort(graph))):
            own = block_cost(node).upper
            tails = [upper_dp[successor] for successor in graph.successors(node)]
            upper_dp[node] = own + (max(tails) if tails else 0)  # type: ignore[operator]
        tail_upper = max(upper_dp[start] for start in block.successors)
        upper = None if suffix.upper is None else suffix.upper + tail_upper

    weighted = nx.DiGraph()
    weighted.add_nodes_from(graph.nodes)
    for source, target in graph.edges:
        weighted.add_edge(source, target, weight=block_cost(target).lower)
    exits = [node for node in graph.nodes if not node.successors]
    tail_lowers = []
    for start in block.successors:
        for exit_block in exits:
            try:
                distance = nx.shortest_path_length(weighted, start, exit_block, weight="weight")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            tail_lowers.append(block_cost(start).lower + distance)
    lower = suffix.lower + (min(tail_lowers) if tail_lowers else 0)
    return lower, upper, tuple(dict.fromkeys(reasons))


def analyze_opcode_budget_guards(prog: SSAProgram) -> list[OpcodeBudgetGuard]:
    """Check whether an asserted OpcodeBudget threshold proves downstream cover.

    ``sufficient`` is a proof and is emitted only for an acyclic, finite-upper
    downstream region. ``insufficient-guarantee`` means the asserted threshold
    itself is below even the cheapest suffix; an execution may still arrive
    with more credit, so it is a review finding rather than a claim of failure.
    """
    facts = prog.facts(FactDomain.CONSTANTS)
    cfg = CFG.of(prog)
    out: list[OpcodeBudgetGuard] = []
    for assertion in prog.assignments:
        shape = _guard_shape(assertion, facts)
        if shape is None:
            continue
        read, relation, threshold = shape
        if relation == ">":
            guaranteed = threshold + 1
        elif relation in {">=", "=="}:
            guaranteed = threshold
        else:
            continue
        lower, upper, reasons = _suffix_cost_bounds(read, assertion, cfg)
        if upper is not None and upper <= guaranteed:
            verdict = "sufficient"
        elif lower is not None and guaranteed < lower:
            verdict = "insufficient-guarantee"
        else:
            verdict = "unknown"
        out.append(OpcodeBudgetGuard(
            read,
            assertion,
            relation,
            threshold,
            guaranteed,
            lower,
            upper,
            verdict,
            reasons,
        ))
    return out


@dataclass(frozen=True)
class BudgetExhaustionCandidate:
    loop: LoopBound
    attacker_controlled: bool
    reason: str


_ATTACKER_READS = frozenset({
    "arg", "args", "txn", "txna", "txnas", "gtxn", "gtxna", "gtxnas",
    "gtxns", "gtxnsa", "gtxnsas",
})


def _attacker_rooted(value, facts, seen=None) -> bool:
    """Whether any definition leaf is attacker-controlled, without recursion."""
    visited = set() if seen is None else set(seen)
    pending = [value]
    while pending:
        current = facts.resolve(pending.pop())
        if isinstance(current, Const):
            continue
        if not isinstance(current, (SSAVar, Phi)):
            return True
        key = id(current)
        if key in visited:
            continue
        visited.add(key)
        if isinstance(current, Phi):
            pending.extend(current.args)
            continue
        definition = current.defined_by
        if definition is None:
            return True
        if definition.op in _ATTACKER_READS:
            return True
        pending.extend(definition.inputs)
    return False


def find_budget_exhaustion_candidates(prog: SSAProgram) -> list[BudgetExhaustionCandidate]:
    """Review candidates where attacker-influenced flow can keep a loop cycling.

    This deliberately does not call the candidate a vulnerability: proving
    semantic progress requires a contract-specific ranking function.  It does
    exclude loops whose only bound is a separately proved stack-growth ceiling.
    """
    facts = prog.facts(FactDomain.CONSTANTS)
    out: list[BudgetExhaustionCandidate] = []
    for loop in analyze_loops(prog):
        controlled = False
        for source, _target in loop.back_edges:
            stream = canonical_assignments(source)
            terminator = next((assignment for assignment in reversed(stream)
                               if assignment.op in {"bnz", "bz", "switch", "match"}), None)
            if terminator is not None and terminator.inputs:
                controlled = controlled or _attacker_rooted(terminator.inputs[0], facts)
        # A growing stack suppresses a *budget* exhaustion candidate only when
        # it provably fails first.  Expensive growing loops can still consume
        # all opcode credit before reaching the depth limit.
        stack_fails_first = (
            loop.stack_bound is not None
            and loop.stack_bound < loop.budget_bound
        )
        if not controlled or stack_fails_first:
            continue
        out.append(BudgetExhaustionCandidate(
            loop,
            True,
            "attacker-influenced continuation with no stack ceiling that fails "
            "before opcode budget; "
            "establish a ranking function or an explicit iteration cap",
        ))
    return out
