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

* **Budget.** Every iteration costs at least ``min_iteration_cost``, and the
  pool affords :data:`MAX_POOLED_OPCODE_BUDGET`. Using the CHEAPEST cycle
  through the loop is what makes this an UPPER bound on iterations — a more
  expensive route through the body only runs fewer times.
* **Stack.** A loop whose cycle leaves the stack net POSITIVE grows it every
  iteration and dies at :data:`MAX_STACK_DEPTH`. A net-zero or net-negative loop
  is unbounded by this ceiling, which is the common case.

HAZARD: these are UPPER bounds on what the AVM permits, never predictions. A
loop bounded at 700 iterations usually runs three times; the bound says only
that the runtime kills it beyond that. Reading a bound as a trip count invents
facts about the program.

HAZARD: each bound is sound ALONE but the set is not jointly tight — nested and
sibling loops share one budget, and every bound spends it as though the others
did not. A loop nested in one bounded at 46 x 15 may itself report 76 x 9, a
pair needing 1374 of the 700 that exists. Use a bound to rule a loop OUT ("at
most 18 iterations, so the index cannot exceed 18"), never to add several up.
Iteration counts are TOTAL across the execution rather than per entry, which is
what makes the inner bound already account for being re-entered by its parent.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from .._utils.dot import (bb_label as _bb_label, escape,
                          header as _dot_header, render as _dot_render)
from ..avm import APP_ONLY_OPS, op_arity
from ..cfg import CFG
from ..ssa import BasicBlock, SSAProgram

#: What ONE application call contributes to the opcode-budget pool.
APP_CALL_OPCODE_BUDGET = 700

#: Application calls in one atomic group. Each contributes its own budget.
MAX_GROUP_APP_CALLS = 16

#: Inner application calls a group can make (16 per app call, pooled across a
#: full group). Each of those ALSO contributes a budget.
MAX_INNER_APP_CALLS = 256

#: A logic signature is metered SEPARATELY and far more generously: its limit is
#: a total program COST, not an app call's opcode budget, and the two never mix.
#: Backward branches (loops) exist only from TEAL v4, where the cost is enforced
#: during execution rather than statically.
LOGICSIG_MAX_COST = 20_000

#: Logic signatures in one group, each with its own cost allowance.
MAX_GROUP_LOGICSIGS = 16

#: The ceiling a loop is bounded against.
#:
#: HAZARD: the budget is POOLED, not per-call, and bounding against a single
#: call's 700 is UNSOUND — it makes every bound ~272x too tight, so a loop that
#: can really run 4000 times reports 18 and the "upper bound" is not one. A
#: contract cannot know at analysis time how large its group is or how many
#: inner calls it will make, so the conservative ceiling is the only sound
#: default: a full group of app calls plus the inner calls they may spawn.
#:
#: Deliberately loose. Group-shape analysis and an inner-call count can tighten
#: it later by passing ``budget=`` to :func:`analyze_loops`; a too-tight default
#: cannot be recovered from, because it silently converts a bound into a claim
#: the program can violate.
MAX_POOLED_OPCODE_BUDGET = APP_CALL_OPCODE_BUDGET * (
    MAX_GROUP_APP_CALLS + MAX_INNER_APP_CALLS
)

#: The same conservative ceiling for a logic signature.
MAX_POOLED_LOGICSIG_COST = LOGICSIG_MAX_COST * MAX_GROUP_LOGICSIGS


def program_mode(prog: SSAProgram) -> str:
    """``"app"`` if the program uses any application-only OPCODE, else
    ``"logicsig"`` — the two are metered by different, non-interchangeable
    limits, so bounding a logicsig against an app call's budget is wrong in
    both directions.

    HAZARD: key on OPCODES the AVM rejects in Signature mode, NEVER on txn
    fields. A logicsig can be attached to an ApplicationCall and so legitimately
    reads ``OnCompletion`` / ``ApplicationArgs`` / ``ApplicationID``; keying on
    those misclassifies that whole class. Same rule and same
    :data:`avm.APP_ONLY_OPS` table as ``security.classify_program``, which
    cannot be imported here — the dependency runs security -> tealtools and
    never back."""
    return ("app" if any(a.op in APP_ONLY_OPS for a in prog.assignments)
            else "logicsig")


def default_budget(prog: SSAProgram) -> int:
    """The conservative ceiling for this program's execution model."""
    return (MAX_POOLED_OPCODE_BUDGET if program_mode(prog) == "app"
            else MAX_POOLED_LOGICSIG_COST)

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
    budget_bound: int          # iterations before the pooled budget dies
    stack_bound: Optional[int] # iterations before the stack cap, or None
    depth: int = 0             # nesting depth; 0 for an outermost loop
    budget: int = MAX_POOLED_OPCODE_BUDGET   # ceiling this was bounded against

    @property
    def available_budget(self) -> int:
        """What is left for the loop after the mandatory prefix."""
        return max(0, self.budget - self.prefix_cost)

    @property
    def max_iterations(self) -> int:
        """Whichever ceiling binds first.

        TOTAL iterations across the whole execution, NOT per entry. A loop
        nested in one that runs K times is entered K times, and this bounds the
        sum — which is the useful reading, because the budget is what is shared.
        Per-entry is bounded by the same number and more loosely."""
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


def _entry_distances(cfg: CFG) -> dict:
    """``block -> cheapest budget to REACH it from a program entry``, the block's
    own cost included. Absent when no entry reaches it."""
    import networkx as nx

    g = nx.DiGraph()
    g.add_nodes_from(cfg.blocks)
    for bb in cfg.blocks:
        for s in bb.successors:
            g.add_edge(bb, s, weight=block_cost(s))     # pay on arrival
    best: dict = {}
    for entry in cfg.entries:
        if entry not in g:
            continue
        base = block_cost(entry)
        for node, d in nx.single_source_dijkstra_path_length(
                g, entry, weight="weight").items():
            total = base + d
            if node not in best or total < best[node]:
                best[node] = total
    return best


def _prefix_cost(cfg: CFG, header: BasicBlock, dist: dict) -> int:
    """Budget CERTAINLY spent before ``header`` can run.

    The execution takes SOME path from an entry to the header, and every path
    costs at least the CHEAPEST one — so the cheapest path's cost is a lower
    bound on what is already gone, and the loop never gets the full 700.

    This subsumes the dominator sum it replaced and is never smaller: every path
    crosses all of the header's dominators, so any path already costs at least
    that much, and the cheapest one usually crosses more blocks besides.

    HAZARD: block costs are NON-NEGATIVE, which is what makes plain Dijkstra
    right here — a back edge can never shorten a path, so a loop on the way to
    this one needs no special handling and the shortest path is always simple.
    The header's own cost is excluded: that belongs to the per-iteration cost,
    and counting it twice would over-subtract and under-report iterations, the
    unsound direction for an upper bound.

    Falls back to the dominator sum for a header no entry reaches (dead code),
    where "the cheapest path" does not exist."""
    reached = dist.get(header)
    if reached is None:
        return sum(block_cost(b) for b in cfg.dominators(header) if b is not header)
    return max(0, reached - block_cost(header))


def analyze_loops(prog: SSAProgram, cfg: Optional[CFG] = None, *,
                  budget: Optional[int] = None) -> "list[LoopBound]":
    """Every natural loop with its cost and iteration bounds, header order.

    ``budget`` is the pooled opcode ceiling, defaulting to the conservative
    maximum. Pass a smaller one once group shape and inner-call count are known
    — bounding against a budget the program might actually exceed is the unsound
    direction."""
    cfg = cfg or CFG.of(prog)
    if budget is None:
        budget = default_budget(prog)
    dist = _entry_distances(cfg)
    out: list[LoopBound] = []
    for header, body, back_edges in _natural_loops(cfg):
        cost, delta = _cheapest_cycle(header, body, back_edges)
        cost = max(1, cost)                      # every cycle charges something
        prefix = _prefix_cost(cfg, header, dist)
        budget_bound = max(0, budget - prefix) // cost
        # Only a net-POSITIVE cycle is bounded by the stack; anything else can
        # spin without growing it.
        stack_bound = (MAX_STACK_DEPTH // delta) if delta > 0 else None
        out.append(LoopBound(
            header=header, body=frozenset(body), back_edges=tuple(back_edges),
            min_iteration_cost=cost, stack_delta=delta, prefix_cost=prefix,
            budget_bound=budget_bound, stack_bound=stack_bound, budget=budget,
        ))
    # Natural loops nest or are disjoint, never partially overlap, so a strict
    # body-subset count is the nesting depth.
    by_depth = [
        replace(lp, depth=sum(1 for other in out
                              if other is not lp and lp.body < other.body))
        for lp in out
    ]
    return sorted(by_depth, key=lambda b: (b.header.file, b.header.first_line))


def render(prog: SSAProgram, cfg: Optional[CFG] = None) -> str:
    """Human-readable loop table."""
    loops = analyze_loops(prog, cfg)
    if not loops:
        return "no loops"
    rows = ["loops (upper bounds on what the AVM PERMITS, not trip counts;",
            " iteration counts are TOTAL across the execution, not per entry):"]
    for b in loops:
        stack = (f", stack {b.stack_delta:+d}/iter" if b.stack_delta else "")
        prefix = (f", {b.prefix_cost} spent before it "
                  f"(budget left {b.available_budget})" if b.prefix_cost else "")
        rows.append(
            "  " + "  " * b.depth +
            f"L{b.header.first_line}-L{b.header.last_line}: "
            f"{len(b.body)} block(s), cheapest iteration {b.min_iteration_cost} "
            f"budget{stack}{prefix} → at most {b.max_iterations} iterations "
            f"({b.bound_reason}-bound)"
        )
    return "\n".join(rows)


# --- visualisation -----------------------------------------------------------


def to_dot(prog: SSAProgram, cfg: Optional[CFG] = None, *,
           file: Optional[str] = None, rankdir: str = "TB") -> str:
    """The CFG with each loop boxed and labelled by its bound, and the budget
    already SPENT before it shown.

    The table says what a loop costs; this says where it sits and what the
    program committed on the way in. Blocks that strictly dominate some loop
    header are tinted as spent — those are the ones subtracted from the 700.

    A block is drawn inside its INNERMOST loop only: DOT clusters may nest but
    not overlap, and natural loops sharing blocks without nesting (irreducible
    control flow) would produce an invalid graph."""
    cfg = cfg or CFG.of(prog)
    loops = analyze_loops(prog, cfg)
    blocks = [b for b in cfg.blocks if file is None or b.file == file]
    shown = set(blocks)

    # innermost loop per block: the smallest body containing it
    owner: dict = {}
    for lp in sorted(loops, key=lambda x: -len(x.body)):
        for bb in lp.body:
            owner[bb] = lp
    spent = {b for lp in loops for b in cfg.dominators(lp.header) if b is not lp.header}
    back = {(u, h) for lp in loops for u, h in lp.back_edges}

    def nid(bb) -> str:
        return f"bb_{bb.first_line}_{bb.last_line}"

    def node_line(bb) -> str:
        cost = block_cost(bb)
        # via bb_label: it escapes each PART then joins with the literal DOT
        # break, where escaping the joined string would double the backslash and
        # print a literal "\n".
        tag = _bb_label(f"L{bb.first_line}-L{bb.last_line}", [f"{cost} budget"])
        if bb in spent and bb not in owner:
            style = 'style="filled", fillcolor="#fdf0d5", color="#b8860b"'
        elif any(bb is lp.header for lp in loops):
            style = 'style="filled,bold", fillcolor="#dbe9ff", color="#1f5fa8", penwidth=2'
        elif bb in owner:
            style = 'style="filled", fillcolor="#eef4ff", color="#7aa0d0"'
        else:
            style = 'style="filled", fillcolor="#f6f6f6", color="#999999"'
        return f'    {nid(bb)} [shape=box, label="{tag}", {style}];'

    out = _dot_header("loop_bounds", rankdir=rankdir)
    index = {lp: i for i, lp in enumerate(loops)}
    # Children of a loop = the loops directly inside it. Natural loops nest or
    # are disjoint, so clusters can be emitted RECURSIVELY and a nested loop is
    # drawn inside its parent instead of beside it.
    children: dict = {None: []}
    for lp in loops:
        parents = [o for o in loops if o is not lp and lp.body < o.body]
        parent = min(parents, key=lambda o: len(o.body)) if parents else None
        children.setdefault(parent, []).append(lp)
        children.setdefault(lp, [])

    def emit(lp, indent: str) -> None:
        label = (f"L{lp.header.first_line}: <= {lp.max_iterations} iter "
                 f"({lp.bound_reason}), {lp.min_iteration_cost}/iter")
        if lp.prefix_cost:
            label += f", {lp.prefix_cost} spent before"
        out.append(f'{indent}subgraph cluster_{index[lp]} {{')
        out.append(f'{indent}  label="{escape(label)}"; color="#1f5fa8"; style=rounded;')
        for kid in children.get(lp, ()):
            emit(kid, indent + "  ")
        for b in blocks:
            if owner.get(b) is lp:
                out.append(node_line(b))
        out.append(indent + "}")

    for lp in children.get(None, ()):
        emit(lp, "  ")
    for bb in blocks:
        if bb not in owner:
            out.append(node_line(bb))
    for bb in blocks:
        for s in bb.successors:
            if s not in shown:
                continue
            attrs = ('[color="#c0392b", style=bold, label="back"]'
                     if (bb, s) in back else "")
            out.append(f"  {nid(bb)} -> {nid(s)} {attrs};")
    out.append("}")
    return "\n".join(out)


def draw(prog: SSAProgram, cfg: Optional[CFG] = None, *, file: Optional[str] = None,
         format: str = "svg", engine: str = "dot", rankdir: str = "TB"):
    """Render :func:`to_dot` (Jupyter-renderable SVG)."""
    return _dot_render(to_dot(prog, cfg, file=file, rankdir=rankdir),
                       format=format, engine=engine)
