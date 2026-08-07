"""Loop extraction with COST and ITERATION BOUNDS.

For each natural loop: what one iteration costs in opcode budget, how the stack
moves across it, and the resulting upper bound on how many times it can run.

Nothing else in the toolkit reasons about execution COST, which leaves a whole
class of questions unaskable — is this sink even reachable inside the budget, can
an attacker spin a loop until the program dies, does this path need more than one
transaction's budget to complete. The per-op costs come from puya's langspec
(``AVMOp.cost``), the same source the metadata drift tests already pin.

Two independent ceilings bound a loop, and the real bound is whichever binds
first:

* **Budget.** Every iteration costs at least ``min_iteration_cost``, and an
  application call gets :data:`APP_OPCODE_BUDGET`. Using the CHEAPEST cycle
  through the loop is what makes this an UPPER bound on iterations — a more
  expensive route through the body only runs fewer times.
* **Stack.** A loop whose cycle leaves the stack net POSITIVE grows it every
  iteration and dies at :data:`MAX_STACK_DEPTH`. A net-zero or net-negative loop
  is unbounded by this ceiling, which is the common case.

HAZARD: these are UPPER bounds on what the AVM permits, never predictions. A
loop bounded at 700 iterations usually runs three times; the bound says only
that the runtime kills it beyond that. Reading a bound as a trip count invents
facts about the program.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .avm import op_arity
from .cfg import CFG
from .ssa import BasicBlock, SSAProgram

#: Opcode budget for a single application call. POOLED across the group, so a
#: 16-transaction group affords 16x this — see :attr:`LoopBound.budget_bound`,
#: which reports the single-call figure.
APP_OPCODE_BUDGET = 700

#: The AVM kills a program whose stack exceeds this.
MAX_STACK_DEPTH = 1000


def op_cost(op: str, immediates: str = "") -> int:
    """Opcode budget one execution of ``op`` consumes, from puya's langspec.

    Unknown opcodes cost 1 — the floor every AVM opcode charges — so a cost
    total is never UNDER-counted into a bigger iteration bound by an op this
    build does not know."""
    variants = _puya_costs()
    return variants.get(op, 1)


_COST_CACHE: Optional[dict] = None


def _puya_costs() -> dict:
    """``mnemonic -> cost``. Empty (so everything costs 1) without puya, which
    keeps this module importable in the puya-free analysis layer."""
    global _COST_CACHE
    if _COST_CACHE is None:
        try:
            from puya.ir.avm_ops import AVMOp
            _COST_CACHE = {m.code: int(m.cost) for m in AVMOp
                           if isinstance(getattr(m, "cost", None), int)}
        except Exception:
            _COST_CACHE = {}
    return _COST_CACHE


def block_cost(bb: BasicBlock) -> int:
    """Opcode budget one pass through ``bb`` consumes."""
    return sum(op_cost(a.op, a.immediates or "") for a in bb.assignments)


def block_stack_delta(bb: BasicBlock) -> int:
    """Net stack change across ``bb`` (pushes minus pops).

    HAZARD: ``callsub`` / ``retsub`` are modelled ``(0, 0)`` by
    :func:`avm.op_arity`, so a subroutine's own argument and return effects are
    NOT counted. A loop whose body calls a stack-changing subroutine therefore
    reports a delta that is only the caller-visible part; treat a net-positive
    result as a signal, not a proof."""
    delta = 0
    for a in bb.assignments:
        n_in, n_out = op_arity(a.op, a.immediates or "")
        delta += n_out - n_in
    return delta


@dataclass(frozen=True)
class LoopBound:
    """One natural loop, with what it costs and how often it can run."""

    header: BasicBlock
    body: frozenset            # every BasicBlock in the loop
    back_edges: tuple          # the (source, header) edges that close it
    min_iteration_cost: int    # budget for the CHEAPEST cycle
    stack_delta: int           # net stack change over that cycle
    prefix_cost: int           # budget CERTAINLY spent before the loop can start
    budget_bound: int          # iterations before a single call's budget dies
    stack_bound: Optional[int] # iterations before the stack cap, or None

    @property
    def available_budget(self) -> int:
        """What is left for the loop after the mandatory prefix."""
        return max(0, APP_OPCODE_BUDGET - self.prefix_cost)

    @property
    def max_iterations(self) -> int:
        """Whichever ceiling binds first."""
        if self.stack_bound is None:
            return self.budget_bound
        return min(self.budget_bound, self.stack_bound)

    @property
    def bound_reason(self) -> str:
        if self.stack_bound is not None and self.stack_bound < self.budget_bound:
            return "stack"
        return "budget"

    @property
    def first_line(self) -> int:
        return self.header.first_line

    def __repr__(self) -> str:
        return (f"Loop(L{self.header.first_line} x{len(self.body)}bb "
                f"cost={self.min_iteration_cost} prefix={self.prefix_cost} "
                f"max_iter={self.max_iterations} by {self.bound_reason})")


def _natural_loops(cfg: CFG) -> "list[tuple[BasicBlock, set, list]]":
    """``(header, body, back_edges)`` per natural loop.

    A back edge is ``u -> h`` where ``h`` DOMINATES ``u``: every path into ``u``
    already passed the header, so the edge closes a genuine loop rather than
    some other cycle. The body is everything that reaches ``u`` without leaving
    through ``h``. Back edges sharing a header are one loop, so a
    multiple-``continue`` loop is not reported several times."""
    by_header: dict = {}
    for u in cfg.blocks:
        for h in u.successors:
            if h in cfg.dominators(u):
                by_header.setdefault(h, []).append((u, h))
    loops = []
    for h, edges in by_header.items():
        body = {h}
        stack = [u for u, _ in edges]
        while stack:
            n = stack.pop()
            if n in body:
                continue
            body.add(n)
            stack.extend(p for p in n.predecessors if p not in body)
        loops.append((h, body, edges))
    return loops


def _cheapest_cycle(header: BasicBlock, body: set, back_edges: list):
    """``(cost, stack_delta)`` of the cheapest route header -> back-edge source,
    staying inside the loop.

    Cheapest, because an upper bound on ITERATIONS needs the lower bound on cost
    per iteration. Dijkstra over the body with blocks as weights."""
    import networkx as nx

    g = nx.DiGraph()
    for bb in body:
        for s in bb.successors:
            if s in body:
                g.add_edge(bb, s, weight=block_cost(s))
    if header not in g:
        return block_cost(header), block_stack_delta(header)

    best = None
    for src, _ in back_edges:
        if src not in g:
            continue
        try:
            path = nx.shortest_path(g, header, src, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        cost = sum(block_cost(b) for b in path)
        if best is None or cost < best[0]:
            best = (cost, sum(block_stack_delta(b) for b in path))
    if best is None:
        return block_cost(header), block_stack_delta(header)
    return best


def _prefix_cost(cfg: CFG, header: BasicBlock) -> int:
    """Budget CERTAINLY spent before ``header`` can run: the cost of its STRICT
    dominators.

    Every path from entry to the header crosses all of them by definition, so
    that budget is gone before the first iteration and the loop never gets the
    full 700. Counting each once is the sound direction — a dominator that is
    itself inside another loop runs MORE than once, which only spends more.

    HAZARD: dominators of the header are necessarily OUTSIDE this loop (a body
    block cannot dominate the entry it is reached through), so nothing here
    double-counts the per-iteration cost."""
    return sum(block_cost(b) for b in cfg.dominators(header) if b is not header)


def analyze_loops(prog: SSAProgram, cfg: Optional[CFG] = None) -> "list[LoopBound]":
    """Every natural loop with its cost and iteration bounds, header order."""
    cfg = cfg or CFG.of(prog)
    out: list[LoopBound] = []
    for header, body, back_edges in _natural_loops(cfg):
        cost, delta = _cheapest_cycle(header, body, back_edges)
        cost = max(1, cost)                      # every cycle charges something
        prefix = _prefix_cost(cfg, header)
        budget_bound = max(0, APP_OPCODE_BUDGET - prefix) // cost
        # Only a net-POSITIVE cycle is bounded by the stack; anything else can
        # spin without growing it.
        stack_bound = (MAX_STACK_DEPTH // delta) if delta > 0 else None
        out.append(LoopBound(
            header=header, body=frozenset(body), back_edges=tuple(back_edges),
            min_iteration_cost=cost, stack_delta=delta, prefix_cost=prefix,
            budget_bound=budget_bound, stack_bound=stack_bound,
        ))
    return sorted(out, key=lambda b: (b.header.file, b.header.first_line))


def render(prog: SSAProgram, cfg: Optional[CFG] = None) -> str:
    """Human-readable loop table."""
    loops = analyze_loops(prog, cfg)
    if not loops:
        return "no loops"
    rows = ["loops (upper bounds on what the AVM PERMITS, not trip counts):"]
    for b in loops:
        stack = (f", stack {b.stack_delta:+d}/iter" if b.stack_delta else "")
        prefix = (f", {b.prefix_cost} spent before it "
                  f"(budget left {b.available_budget})" if b.prefix_cost else "")
        rows.append(
            f"  L{b.header.first_line}-L{b.header.last_line}: "
            f"{len(b.body)} block(s), cheapest iteration {b.min_iteration_cost} "
            f"budget{stack}{prefix} → at most {b.max_iterations} iterations "
            f"({b.bound_reason}-bound)"
        )
    return "\n".join(rows)
