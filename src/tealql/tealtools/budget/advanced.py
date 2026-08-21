"""Higher-level resource queries built on cost and loop facts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from ..analysis import FactDomain
from ..cfg import CFG
from ..ssa import Assignment, BasicBlock, Const, Phi, SSAProgram, SSAVar, binary_operands, const_int
from ..cfg.structure import analyze_structure
from .context import BudgetContext, context_for
from .costs import CostFact, CostModel, canonical_assignments, sum_costs
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


def _suffix_cost_bounds(
    read: Assignment, enforcement: Assignment, cfg: CFG, model: CostModel,
):
    block = read.basic_block
    if block is None or enforcement.basic_block is not block:
        return None, None, ("budget read and enforcement are in different blocks",)
    stream = canonical_assignments(block)
    try:
        read_index = next(i for i, assignment in enumerate(stream) if assignment is read)
    except StopIteration:
        return None, None, ("budget read is absent from canonical stream",)
    suffix = sum_costs(
        model.assignment_cost(assignment)
        for assignment in stream[read_index + 1:]
    )
    reasons = list(suffix.reasons)
    if not block.successors:
        return suffix.lower, suffix.upper, tuple(reasons)

    graph = _reachable_graph(cfg, block.successors)
    if not nx.is_directed_acyclic_graph(graph):
        reasons.append("a reachable cycle makes downstream upper cost unbounded")
        upper = None
    elif any(model.block_cost(node).upper is None for node in graph.nodes):
        reasons.append("dynamic opcode cost has no finite downstream upper bound")
        upper = None
    else:
        upper_dp: dict[BasicBlock, int] = {}
        for node in reversed(list(nx.topological_sort(graph))):
            own = model.block_cost(node).upper
            tails = [upper_dp[successor] for successor in graph.successors(node)]
            upper_dp[node] = own + (max(tails) if tails else 0)  # type: ignore[operator]
        tail_upper = max(upper_dp[start] for start in block.successors)
        upper = None if suffix.upper is None else suffix.upper + tail_upper

    weighted = nx.DiGraph()
    weighted.add_nodes_from(graph.nodes)
    for source, target in graph.edges:
        weighted.add_edge(
            source, target, weight=model.block_cost(target).lower
        )
    exits = [node for node in graph.nodes if not node.successors]
    tail_lowers = []
    for start in block.successors:
        for exit_block in exits:
            try:
                distance = nx.shortest_path_length(weighted, start, exit_block, weight="weight")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            tail_lowers.append(model.block_cost(start).lower + distance)
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
    model = CostModel(prog)
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
        lower, upper, reasons = _suffix_cost_bounds(read, assertion, cfg, model)
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


_ORDERING_OPS = frozenset({"<", "<=", ">", ">="})
_NEGATE_ORDERING = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _continuation_relation(prog: SSAProgram, loop: LoopBound, block: BasicBlock,
                           relation: str) -> Optional[str]:
    """The ordering relation that must hold to stay in ``loop``.

    The comparison result is not necessarily the continuation condition: ``bnz done``
    continues on the comparison's FALSE arm.  Use the CFG builder's canonical edge
    polarity rather than recovering labels a second time.
    """
    polarities = getattr(prog, "edge_polarity", {})

    def labels(successors) -> set[str]:
        return {
            label
            for successor in successors
            for label in polarities.get((block._key(), successor._key()), ())
        }

    inside = labels(successor for successor in block.successors
                    if successor in loop.body)
    outside = labels(successor for successor in block.successors
                     if successor not in loop.body)
    if inside == {"true"} and outside == {"false"}:
        return relation
    if inside == {"false"} and outside == {"true"}:
        return _NEGATE_ORDERING[relation]
    return None


def _same_induction_value(prog: SSAProgram, value, counter: Phi, facts) -> bool:
    value = facts.resolve(value)
    if value == counter:
        return True
    # Nested loops materialize an intermediate phi for values they carry through.
    # Credit it only when the structural phi chain starts at ``counter`` AND its
    # complete leaf set is identical; mere reachability through a mixed merge is
    # not an identity proof.
    return (
        isinstance(value, Phi)
        and not value.partial
        and prog.chain_root(value) == counter
        and set(value.args) == set(counter.args)
    )


def _positive_induction_step(prog: SSAProgram, value, counter: Phi,
                             relation: str, facts) -> Optional[int]:
    """Constant progress made by one back edge, or ``None`` without a proof."""
    value = facts.resolve(value)
    definition = getattr(value, "defined_by", None)
    if definition is None:
        return None
    operands = binary_operands(definition)
    if operands is None:
        return None
    lhs, rhs = operands

    if relation in {"<", "<="} and definition.op == "+":
        pairs = ((lhs, rhs), (rhs, lhs))
    elif relation in {">", ">="} and definition.op == "-":
        pairs = ((lhs, rhs),)
    else:
        return None
    for base, step_value in pairs:
        if not _same_induction_value(prog, base, counter, facts):
            continue
        step = const_int(facts.resolve(step_value))
        if step is not None and step > 0:
            return step
    return None


def _iterations_to_bound(initial: int, bound: int, step: int, relation: str) -> int:
    """Maximum successful continuation tests for one monotone induction value."""
    if relation == "<":
        return 0 if initial >= bound else (bound - initial + step - 1) // step
    if relation == "<=":
        return 0 if initial > bound else (bound - initial) // step + 1
    if relation == ">":
        return 0 if initial <= bound else (initial - bound + step - 1) // step
    return 0 if initial < bound else (initial - bound) // step + 1


def _constant_trip_cap(prog: SSAProgram, loop: LoopBound, facts) -> Optional[int]:
    """An explicit iteration cap the loop already carries, or ``None``.

    Suppression is a proof, so a constant comparison alone is not enough.  The
    counter must be a reducible-loop header phi; every entry value must be a
    constant; every back edge must update it by a positive constant in the
    direction that falsifies the continuation relation.  This recognises the
    ubiquitous ``for (i = 0; i < 24; i += 1)`` shape without hiding unchanged,
    backwards-moving, or branch-polarity-inverted loops.

    Only the blocks that DECIDE CONTINUATION are inspected.  A conditional inside the body may well
    test attacker data without having any say in how many laps run, and treating those alike is what
    makes a bounded counting loop look unbounded.
    """
    if loop.kind != "reducible":
        return None
    caps: list[int] = []
    for block in loop.body:
        # Every lap enters a reducible loop through its header.  A guard deeper in
        # the body may be bypassed by another cycle and therefore cannot bound the
        # region as a whole without a separate dominance proof.
        if block is not loop.header:
            continue
        inside = any(successor in loop.body for successor in block.successors)
        outside = any(successor not in loop.body for successor in block.successors)
        if not (inside and outside):
            continue
        stream = canonical_assignments(block)
        terminator = next((a for a in reversed(stream) if a.op in {"bnz", "bz"}), None)
        if terminator is None or not terminator.inputs:
            continue
        condition = facts.resolve(terminator.inputs[0])
        definition = getattr(condition, "defined_by", None)
        if definition is None or definition.op not in _ORDERING_OPS:
            continue
        operands = binary_operands(definition)
        if operands is None:
            continue
        lhs, rhs = operands
        for counter_value, limit, relation in (
            (lhs, rhs, definition.op),
            (rhs, lhs, _FLIP[definition.op]),
        ):
            bound = const_int(facts.resolve(limit))
            if bound is None:
                continue
            counter = facts.resolve(counter_value)
            if (not isinstance(counter, Phi) or counter.partial
                    or counter.basic_block is not loop.header):
                continue
            relation = _continuation_relation(prog, loop, block, relation)
            if relation is None:
                continue

            initials: list[int] = []
            steps: list[int] = []
            complete = True
            for predecessor in loop.header.predecessors:
                incoming = predecessor.slot(counter.stack_index)
                if incoming is None:
                    complete = False
                    break
                if predecessor in loop.body:
                    step = _positive_induction_step(prog, incoming, counter, relation, facts)
                    if step is None:
                        complete = False
                        break
                    steps.append(step)
                else:
                    initial = const_int(facts.resolve(incoming))
                    if initial is None:
                        complete = False
                        break
                    initials.append(initial)
            if complete and initials and steps:
                slowest_step = min(steps)
                caps.append(max(
                    _iterations_to_bound(initial, bound, slowest_step, relation)
                    for initial in initials
                ))
                break
    return min(caps) if caps else None


def constant_trip_cap(prog: SSAProgram, loop: LoopBound) -> Optional[int]:
    """Return a proof-backed semantic trip cap for ``loop``, when one is present.

    Unlike :attr:`LoopBound.max_iterations`, this is not the number of laps the available
    opcode budget can fund.  It recognizes a counter/constant guard already in the program
    and proves that every back edge advances that counter toward termination.  Consumers
    may therefore use it as an independent bound when computing a worst-case program cost.
    """
    return _constant_trip_cap(prog, loop, prog.facts(FactDomain.CONSTANTS))


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
        # A conventional while-loop branches OUT at its header and returns on
        # an unconditional ``b header`` back edge.  Looking only at the
        # back-edge terminator therefore misses the condition that actually
        # decides whether another lap executes.  Inspect every loop block whose
        # branch partitions successors between the loop body and its exits,
        # while retaining conditional back edges for do/while shapes.
        back_edge_sources = {source for source, _target in loop.back_edges}
        for block in loop.body:
            inside = any(successor in loop.body for successor in block.successors)
            outside = any(successor not in loop.body for successor in block.successors)
            if block not in back_edge_sources and not (inside and outside):
                continue
            stream = canonical_assignments(block)
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
        # An explicit cap the loop already carries settles it: if the counter cannot exceed a
        # constant, and that constant is within what the budget affords, the loop CANNOT exhaust the
        # budget however attacker-influenced its body is.  Reporting it anyway asks a reviewer to add
        # the very cap that is already there -- measured on Reti's ValidatorRegistry, ten of ten
        # candidates were counting loops bounded by StaticArray capacities of 3 to 24, against
        # reported bounds of 2840 to 12687 iterations.
        cap = _constant_trip_cap(prog, loop, facts)
        # Keep one iteration of slack for the final header test that proves the
        # loop is done; ``budget_bound`` counts complete cycles, not that exit check.
        capped_within_budget = cap is not None and cap < loop.budget_bound
        if not controlled or stack_fails_first or capped_within_budget:
            continue
        out.append(BudgetExhaustionCandidate(
            loop,
            True,
            "attacker-influenced continuation with no stack ceiling that fails "
            "before opcode budget; "
            "establish a ranking function or an explicit iteration cap",
        ))
    return out
