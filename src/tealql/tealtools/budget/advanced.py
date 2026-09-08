"""Higher-level resource queries built on cost and loop facts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from ..analysis import FactDomain
from ..cfg import CFG
from ..language.avm import VALUE_FLOW_OPAQUE_READ_OPS
from ..ssa import Assignment, BasicBlock, Const, Phi, SSAProgram, SSAVar, binary_operands, const_int
from ..cfg.structure import analyze_structure
from .context import BudgetContext, context_for
from .costs import CostFact, CostModel, canonical_assignments, sum_costs
from .loop_bounds import LoopBound, analyze_loops
from .queries import MinimumCost


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

    # ONE pair of whole-program searches shared across every exit: calling
    # `minimum_cost` per approving exit rebuilt the CFG, the cost model, the
    # predicate fixpoint and both Dijkstras N·M times for a router with N
    # handlers × M exits.
    shared = None

    def _shared():
        nonlocal shared
        if shared is None:
            from ..cfg import CFG
            from ..cfg.path_predicates import PathPredicateAnalysis
            from .queries import _all_distances
            cfg = CFG.of(prog)
            model = CostModel(prog, avm_version=ctx.avm_version)
            pp = PathPredicateAnalysis(prog)
            _ld, lower_paths = _all_distances(cfg, model, pp, upper=False)
            _ud, upper_paths = _all_distances(cfg, model, pp, upper=True)
            shared = (model, lower_paths, upper_paths)
        return shared

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
        results = []
        if approving:
            from .queries import _minimum_cost_from_maps
            model, lower_paths, upper_paths = _shared()
            results = [
                _minimum_cost_from_maps(
                    exit_assignment, ctx, model, lower_paths, upper_paths)
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
    from .upper_cost import UpperCost
    execution = UpperCost(cfg.prog, model=model).after_read(read)
    upper = execution.upper
    reasons.extend(execution.reasons)

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

    ``sufficient`` is a proof and requires a finite upper cost for every
    downstream execution, including independently bounded loops and calls. ``insufficient-guarantee`` means the asserted threshold
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

#: Reads whose RESULT is external to the value walk — a scratch slot the facts
#: layer could not resolve, a group SIBLING's scratch (attacker-assembled
#: group), stored app/asset/box state. Walking into their INPUTS (a slot index,
#: a key) says nothing about the value itself.
_OPAQUE_LEAF_OPS = VALUE_FLOW_OPAQUE_READ_OPS | frozenset({
    "load", "loads", "gload", "gloads", "gloadss",
})


def _attacker_rooted(value, facts, seen=None) -> bool:
    """Whether any definition leaf is attacker-controlled, without recursion.

    HAZARD: for a REVIEW-candidate generator, an UNKNOWN leaf must count as
    attacker-possible. The walk used to simply die at a no-input opaque read
    (`load` of a multi-store slot, `gloads` of a group sibling's scratch) and
    return False — silently excluding every scratch- or group-conditioned loop,
    inverting the repo convention that unknown scratch is a SOURCE."""
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
        if definition.op in _OPAQUE_LEAF_OPS:
            return True
        pending.extend(definition.inputs)
    return False


#: Terminators that can decide loop continuation. ONE set for every consumer:
#: the candidate scan and the cap check each hand-rolled theirs and drifted
#: ({bnz,bz,switch,match} vs {bnz,bz}), so a switch-continued loop could
#: become a candidate the cap check could never inspect.
_EXIT_DECIDING_OPS = frozenset({"bnz", "bz", "switch", "match"})


def _exit_deciding_terminators(loop: LoopBound, extra_blocks: frozenset = frozenset()):
    """``(block, terminator)`` for each loop block whose branch partitions
    successors between body and exit (plus ``extra_blocks``, for conditional
    back edges in do/while shapes) — the blocks that DECIDE CONTINUATION."""
    for block in loop.body:
        inside = any(s in loop.body for s in block.successors)
        outside = any(s not in loop.body for s in block.successors)
        if block not in extra_blocks and not (inside and outside):
            continue
        stream = canonical_assignments(block)
        terminator = next(
            (a for a in reversed(stream) if a.op in _EXIT_DECIDING_OPS), None)
        if terminator is not None and terminator.inputs:
            yield block, terminator


def _constant_trip_cap(prog: SSAProgram, loop: LoopBound, facts) -> Optional[int]:
    return prog.facts(FactDomain.RANGES).loop_analysis().summary(loop).trip_bound


def constant_trip_cap(prog: SSAProgram, loop: LoopBound) -> Optional[int]:
    """Return a proof-backed semantic trip cap for ``loop``, when one is present.

    Unlike :attr:`LoopBound.max_iterations`, this is not the number of laps the available
    opcode budget can fund.  It recognizes counter progress toward a bounded guard
    and proves that every back edge advances that counter toward termination.
    It covers supported stack/scratch and pre/post-test forms. Consumers may use
    it as an independent bound when computing a worst-case program cost. The
    historical name remains compatible; the limit need not be a literal.
    """
    return _constant_trip_cap(prog, loop, prog.facts(FactDomain.CONSTANTS))


def find_budget_exhaustion_candidates(
    prog: SSAProgram, *, guaranteed_entry_credit: Optional[int] = None,
) -> list[BudgetExhaustionCandidate]:
    """Review candidates where attacker-influenced flow can keep a loop cycling.

    This deliberately does not call the candidate a vulnerability: proving
    semantic progress requires a contract-specific ranking function.  It does
    require independent upper-cost and guaranteed-credit evidence for suppression.
    """
    if guaranteed_entry_credit is not None and guaranteed_entry_credit < 0:
        raise ValueError("guaranteed entry credit must be non-negative")
    facts = prog.facts(FactDomain.CONSTANTS)
    cfg = CFG.of(prog)
    covering = None
    entry_upper = None
    if guaranteed_entry_credit is not None:
        from .upper_cost import UpperCost
        costs = UpperCost(prog)
        bounds = [costs.from_block(entry).upper for entry in cfg.entries]
        if bounds and all(bound is not None for bound in bounds):
            entry_upper = max(bounds)
    out: list[BudgetExhaustionCandidate] = []
    for loop in analyze_loops(prog):
        controlled = False
        # A conventional while-loop branches OUT at its header and returns on
        # an unconditional ``b header`` back edge.  Looking only at the
        # back-edge terminator therefore misses the condition that actually
        # decides whether another lap executes.  Inspect every loop block whose
        # branch partitions successors between the loop body and its exits,
        # while retaining conditional back edges for do/while shapes.
        back_edge_sources = frozenset(
            source for source, _target in loop.back_edges)
        for _block, terminator in _exit_deciding_terminators(
                loop, extra_blocks=back_edge_sources):
            controlled = controlled or _attacker_rooted(
                terminator.inputs[0], facts)
        # A credit CEILING and a cheapest-cycle cost cannot prove affordability,
        # including the old claim that stack failure must happen before budget.
        if not controlled:
            continue
        if covering is None:
            covering = analyze_opcode_budget_guards(prog)
        if any(check.sufficient and check.enforcement.basic_block in cfg.dominators(loop.header)
               for check in covering):
            continue
        if entry_upper is not None and entry_upper <= guaranteed_entry_credit:
            continue
        cap = _constant_trip_cap(prog, loop, facts)
        out.append(BudgetExhaustionCandidate(
            loop,
            True,
            (f"attacker-influenced continuation with a proved trip cap of {cap}, "
             "but no proof that execution fits guaranteed opcode credit"
             if cap is not None else
             "attacker-influenced continuation without a proved ranking function "
             "or sufficient guaranteed opcode credit"),
        ))
    return out
