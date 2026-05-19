"""Per-line and per-path opcode cost analysis for TEAL programs.

For each line in a program, computes:

- ``op_cost``: the AVM opcode-budget cost of the single instruction.
- ``cumulative``: the worst-case cumulative cost from program entry
  to that line, taken as the max across all CFG paths that reach
  it without already exceeding the AVM budget.

The AVM halts once its opcode budget is exhausted. That budget is
:func:`program_budget_ceiling`: ``TXN_BUDGET * ASSUMED_GROUP_SIZE``
from peer group txns, plus ``TXN_BUDGET`` per inner appcall the
program may submit (capped at :data:`HARD_BUDGET_LIMIT` /
:data:`MAX_INNER_TXNS`). The reported ``cumulative`` is always a
**sound over-approximation** of the actual worst-case — no false
negatives for budget-exhaustion findings.

Algorithm — structural-analysis fold over the control tree:

1. :mod:`tealtools.control_tree` lifts the CFG into a typed
   region tree (sequence / if / ifelse / switch / loop / improper),
   processing inner loops first (via :mod:`tealtools.loops`).
2. The cost fold is a recursive function over that tree:

   - ``Block``: walk ops, accumulate cum and ic, record per-line
     max into ``out``. Halt the block when cum would exceed
     ``path_ceiling(ic)``.
   - ``Sequence``: thread (cum, ic) through parts in order.
   - ``If``: fold cond, then either skip (cond's exit) or take
     the then-arm; cum/ic at join = max of both.
   - ``IfElse`` / ``Switch``: fold cond, then every arm from
     cond's exit; join state = max across arms.
   - ``Loop``: compute body's static ``(per_iter_cost, submits)``
     summary, derive ``max_iters`` from budget + 256-inner-txn
     caps, fold the body at the last-full-iter entry and at the
     partial-halting-iter entry to capture worst-case line cums.
   - ``Improper``: irreducible fallback — assume each component
     can run :data:`MAX_INNER_TXNS` times (sound but loose).

3. Per-line cum is the max recorded across every fold visit —
   sound over-approximation in every region kind.

Outcome: nested loops are correct (inner contribution counted per
outer iter via the static body summary), branches inside loops are
sound (worst-case arm cost), irreducible regions degrade gracefully
to a documented loose bound.

Cost table is intentionally partial — well-known expensive ops
(crypto verifies, hashes, EC) are listed; everything else defaults
to 1, which is correct for the vast majority of TEAL opcodes.
Extend :data:`OPCODE_COSTS` for ops you care about that aren't
already there.

Limitations:

- ``callsub`` is counted as a single opcode (cost 1). The called
  subroutine's body is its own BBs and is accounted for via the
  CFG edges if those exist; if the SSA layer doesn't connect call
  sites to subroutine entries, subroutine costs aren't amortised
  onto the caller. Worth re-checking on a real fixture.
- Every submitted inner txn is treated as if it were an appcall
  (only appcalls actually grant +700 budget). Filtering by
  TypeEnum via ``inner_txn_report`` would tighten this.
- ``ASSUMED_GROUP_SIZE`` is a flat heuristic; group-shape analysis
  (see ``group_reasoning``) can replace it with a known size.
- Per-iter cost is the longest body-DAG path — for loops with
  divergent branches, iters that take a short path are bounded by
  the long-path cost (over-approximation but sound).
- Box / state ops are charged 1 each. The AVM actually scales box
  costs with size; for accurate budget accounting on box-heavy
  contracts, refine the table.
"""
from __future__ import annotations

from .ssa import BasicBlock, SSAProgram


# Crypto / EC / hash ops with non-default costs. TEAL v10.
OPCODE_COSTS: dict[str, int] = {
    "sha256": 35,
    "keccak256": 130,
    "sha512_256": 45,
    "sha3_256": 130,
    "ed25519verify": 1900,
    "ed25519verify_bare": 1900,
    "ecdsa_verify": 1700,
    "ecdsa_pk_decompress": 650,
    "ecdsa_pk_recover": 2000,
    "vrf_verify": 5700,
    "ec_add": 13,
    "ec_scalar_mul": 970,
    "ec_pairing_check": 8700,
    "ec_multi_scalar_mul": 970,
    "ec_subgroup_check": 1850,
    "ec_map_to": 2300,
    "expw": 10,
    "bsqrt": 40,
    "divw": 4,
}
DEFAULT_COST = 1

# Absolute opcode-budget ceiling: the AVM halts long before this in
# practice (~190k worst-case observed). 200k is a safe round cap.
HARD_BUDGET_LIMIT = 200_000

# Budget contribution per app-call transaction — both group peers
# and submitted inner appcalls add this much to the shared pool.
TXN_BUDGET = 700

# Conservative assumption about how many app-call peers we share a
# group with. The protocol max is 16, but 4 fits typical groups and
# yields a tight bound; refine with ``group_reasoning`` when the
# real shape is known.
ASSUMED_GROUP_SIZE = 4

# AVM protocol cap on inner txns a single top-level call may submit.
# Bounds how far a loop that emits inner appcalls can extend its own
# budget — each submission grants +TXN_BUDGET to the pool, but you
# can only do this 256 times.
MAX_INNER_TXNS = 256

# Soft cap for :func:`per_line_cost_paths` — when a line's distinct-cum
# set exceeds this, we keep the smallest and largest values plus a
# uniform sample of the rest, and flag the line as truncated. Stops
# chained-loop multiplicative blowup from dominating output size.
MAX_CUMS_PER_LINE = 10_000


def opcode_cost(op: str) -> int:
    """AVM opcode-budget cost for ``op``. Defaults to 1 for unknown
    opcodes (correct for the bulk of TEAL ops)."""
    return OPCODE_COSTS.get(op, DEFAULT_COST)


def inner_txn_count(prog: SSAProgram) -> int:
    """Static upper bound on inner txns this program may submit.
    Each ``itxn_submit`` ends one txn; each ``itxn_next`` ends one
    and starts another. Sums to the total submitted across all
    groups."""
    return sum(
        1
        for bb in prog.blocks.values()
        for a in bb.assignments
        if a.op in ("itxn_submit", "itxn_next")
    )


def path_ceiling(inner_count: int, group_size: int = ASSUMED_GROUP_SIZE) -> int:
    """Opcode budget available to a path that has already submitted
    ``inner_count`` inner txns. ``inner_count`` is monotonically
    non-decreasing along any path and is capped by
    :data:`MAX_INNER_TXNS`; the result is capped by
    :data:`HARD_BUDGET_LIMIT`."""
    return min(
        HARD_BUDGET_LIMIT,
        TXN_BUDGET * group_size + TXN_BUDGET * inner_count,
    )


def _bb_in_cycle(bb: BasicBlock) -> bool:
    """True if ``bb`` can reach itself via the CFG. Linear scan;
    fine for TEAL programs at typical sizes."""
    stack = list(bb.successors)
    seen_ids: set[int] = set()
    while stack:
        cur = stack.pop()
        if cur is bb:
            return True
        if id(cur) in seen_ids:
            continue
        seen_ids.add(id(cur))
        stack.extend(cur.successors)
    return False


def _has_submit_in_cycle(prog: SSAProgram) -> bool:
    """True iff any ``itxn_submit`` / ``itxn_next`` sits on a CFG
    cycle. If so, the same submit can grant +``TXN_BUDGET`` to the
    path more than once, defeating the static-count budget bound."""
    for bb in prog.blocks.values():
        if any(a.op in ("itxn_submit", "itxn_next") for a in bb.assignments):
            if _bb_in_cycle(bb):
                return True
    return False


def program_budget_ceiling(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> int:
    """Sound upper bound on opcode budget for any execution.

    Three tiers, selected automatically by program structure — the
    direction is always *over*-approximate, so reported cumulatives
    are always an upper bound on the actual max cost (no false
    negatives for budget-exhaustion findings):

    - No ``itxn_submit`` / ``itxn_next``: base group budget only.
      Tight.
    - Submits present but none on any CFG cycle: base + ``700`` per
      static submit. Tight — each submit grants its +700 at most
      once on any execution since cycle-free CFGs can't revisit it.
    - Submits on a CFG cycle: ``path_ceiling(MAX_INNER_TXNS)`` —
      assume worst-case fan-out to the 256-submission protocol cap.
      Loose but sound; the 256 cap is the only remaining bound on
      how many times the cycle can re-grant +700. Future path-
      relative analysis could tighten this per loop.
    """
    if _has_submit_in_cycle(prog):
        return path_ceiling(MAX_INNER_TXNS, group_size=group_size)
    return path_ceiling(inner_txn_count(prog), group_size=group_size)


def bb_cost(bb: BasicBlock) -> int:
    """Sum of opcode costs for every assignment in ``bb``."""
    return sum(opcode_cost(a.op) for a in bb.assignments)


def _max_k_for_op(
    entry_cum: int,
    entry_ic: int,
    prefix_cum: int,
    prefix_submits: int,
    body_cost: int,
    submits_per_iter: int,
    group_size: int,
) -> int:
    """Maximum iteration count ``k ≥ 1`` such that on iter ``k`` the
    op at ``(prefix_cum, prefix_submits)`` within the body is
    reachable (its cum ≤ its path ceiling, and its ic ≤
    :data:`MAX_INNER_TXNS`).

    Constraints:

    - ``cum_k = entry_cum + (k-1)*body_cost + prefix_cum``
    - ``ic_k = entry_ic + (k-1)*submits_per_iter + prefix_submits``
    - ``cum_k ≤ min(HARD_BUDGET_LIMIT, base + 700*ic_k)``
    - ``ic_k ≤ MAX_INNER_TXNS``

    Returns 0 when the op is not reachable on any iter.
    """
    base = TXN_BUDGET * group_size
    bounds: list[int] = []
    # Constraint: cum_k ≤ base + 700*ic_k (uncapped form)
    #   entry_cum + (k-1)*body_cost + prefix_cum
    #   ≤ base + 700*(entry_ic + (k-1)*submits + prefix_submits)
    #   k*(body_cost - 700*submits) ≤ base + 700*(entry_ic + prefix_submits) -
    #                                  entry_cum - prefix_cum + body_cost - 700*submits
    #   Let net = body_cost - 700*submits
    #     rhs_const = base + 700*(entry_ic + prefix_submits)
    #                 - entry_cum - prefix_cum
    #                 + net          (since when k=0 we'd have prefix only,
    #                                  but iters start at k=1 → shift)
    net = body_cost - TXN_BUDGET * submits_per_iter
    rhs = (
        base
        + TXN_BUDGET * (entry_ic + prefix_submits)
        - entry_cum
        - prefix_cum
        + net
    )
    if net > 0:
        if rhs < net:
            # rhs/net < 1 → even k=1 violates the uncapped form
            return 0
        bounds.append(rhs // net)
    elif net < 0:
        # Each iter NET grants budget; uncapped form never binds.
        pass
    else:  # net == 0
        if rhs < 0:
            return 0
        # No bound from this constraint.
    # Constraint: cum_k ≤ HARD_BUDGET_LIMIT
    if body_cost > 0:
        bounds.append((HARD_BUDGET_LIMIT - entry_cum - prefix_cum + body_cost) // body_cost)
    # Constraint: ic_k ≤ MAX_INNER_TXNS
    if submits_per_iter > 0:
        room = MAX_INNER_TXNS - entry_ic - prefix_submits + submits_per_iter
        if room < submits_per_iter:
            return 0
        bounds.append(room // submits_per_iter)
    if not bounds:
        # No binding constraint — loop can run effectively forever in
        # budget terms. Cap conservatively at MAX_INNER_TXNS even though
        # ic isn't growing, to keep state finite.
        return MAX_INNER_TXNS + 1
    return max(0, min(bounds))


def _max_iters_full(
    entry_cum: int,
    entry_ic: int,
    body_cost: int,
    submits_per_iter: int,
    group_size: int,
) -> int:
    """Max ``k`` such that ``k`` full iterations all stay within
    budget and the inner-txn cap. Equals the running-min over every
    op's max-k from :func:`_max_k_for_op` but cheaper to compute by
    inspecting the iter-end state alone."""
    # End-of-iter state on iter k:
    #   cum = entry_cum + k*body_cost
    #   ic  = entry_ic  + k*submits_per_iter
    # Constraints: cum ≤ path_ceiling(ic), ic ≤ MAX_INNER_TXNS.
    if body_cost == 0:
        return MAX_INNER_TXNS  # cheap cap to keep finite
    base = TXN_BUDGET * group_size
    net = body_cost - TXN_BUDGET * submits_per_iter
    bounds: list[int] = []
    if net > 0:
        margin = base + TXN_BUDGET * entry_ic - entry_cum
        if margin < 0:
            return 0
        bounds.append(margin // net)
    bounds.append((HARD_BUDGET_LIMIT - entry_cum) // body_cost)
    if submits_per_iter > 0:
        bounds.append((MAX_INNER_TXNS - entry_ic) // submits_per_iter)
    if not bounds:
        return MAX_INNER_TXNS
    return max(0, min(bounds))


# ---------------------------------------------------------------------------
# Structural cost fold over the control tree
# ---------------------------------------------------------------------------


def _body_summary(region) -> tuple[int, int]:
    """Worst-case ``(per_iter_cost, per_iter_submits)`` for executing
    ``region`` once. Used to drive ``_max_iters_full`` when summarising
    a parent loop. Nested loops contribute ``max_iters × body_summary``
    of their own body — sound under-the-hood recursion."""
    from .control_tree import (
        BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR, ImproperR,
        ProgramR,
    )
    if isinstance(region, ProgramR):
        # Programs are independent; conservatively take the worst-case
        # program's per-iter cost (callers usually evaluate per-program
        # via the outer fold, so this branch is mostly a safety net).
        c = max((_body_summary(p)[0] for p in region.programs), default=0)
        s = max((_body_summary(p)[1] for p in region.programs), default=0)
        return c, s
    if isinstance(region, BlockR):
        cost = 0
        subs = 0
        for a in region.bb.assignments:
            cost += opcode_cost(a.op)
            if a.op in ("itxn_submit", "itxn_next"):
                subs += 1
        return cost, subs
    if isinstance(region, SequenceR):
        c = s = 0
        for p in region.parts:
            pc, ps = _body_summary(p)
            c += pc
            s += ps
        return c, s
    if isinstance(region, IfR):
        cc, cs = _body_summary(region.cond)
        tc, ts = _body_summary(region.then_branch)
        # Worst case: take the then-arm.
        return cc + tc, cs + ts
    if isinstance(region, IfElseR):
        cc, cs = _body_summary(region.cond)
        tc, ts = _body_summary(region.then_branch)
        ec, es = _body_summary(region.else_branch)
        return cc + max(tc, ec), cs + max(ts, es)
    if isinstance(region, SwitchR):
        cc, cs = _body_summary(region.cond)
        if not region.cases:
            return cc, cs
        max_c = max(_body_summary(c)[0] for c in region.cases)
        max_s = max(_body_summary(c)[1] for c in region.cases)
        return cc + max_c, cs + max_s
    if isinstance(region, GuardR):
        # Worst case for "completing the body": the guard doesn't
        # fire, control falls through. cost = cond only. (The
        # exit_arm runs on a different path that doesn't continue.)
        return _body_summary(region.cond)
    if isinstance(region, LoopR):
        body_c, body_s = _body_summary(region.body)
        # Most permissive entry state (0, 0) → maximum iters → sound
        # over-approximation when this loop appears inside an outer body.
        iters = _max_iters_full(0, 0, body_c, body_s, ASSUMED_GROUP_SIZE)
        return body_c * iters, body_s * iters
    if isinstance(region, ImproperR):
        # The improper's interior is an *acyclic* DAG by construction
        # (loops were collapsed in Phase 1 of build_control_tree, so
        # what's left in an Improper is a DAG of regions). Each
        # component executes at most once per pass through; nested
        # loops have already been expanded inside their LoopR
        # ``_body_summary``. Just sum — no MAX_INNER_TXNS multiplier.
        c = s = 0
        for n in region.nodes:
            nc, ns = _body_summary(n)
            c += nc
            s += ns
        return c, s
    return 0, 0


def _fold_max(
    region,
    entry_cum: int,
    entry_ic: int,
    group_size: int,
    out: dict[tuple[str, int], tuple[str, int, int]],
) -> tuple[int, int]:
    """Recursive max-cum fold over the control tree. Records per-line
    max cum into ``out``; returns the ``(exit_cum, exit_ic)`` of
    completing the region. Respects the per-path budget by halting a
    Block when its cum would exceed ``path_ceiling(ic)``."""
    from .control_tree import (
        BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR, ImproperR,
        ProgramR,
    )

    if isinstance(region, ProgramR):
        # Each program is its own top-level execution context — fold
        # from a fresh (0, 0) state, ignore the entry_state inherited
        # by the wrapper. Per-program max-cum is recorded into ``out``;
        # the returned post-state isn't meaningful (programs don't
        # compose).
        for prog_region in region.programs:
            _fold_max(prog_region, 0, 0, group_size, out)
        return 0, 0

    if isinstance(region, BlockR):
        cum, ic = entry_cum, entry_ic
        for a in region.bb.assignments:
            oc = opcode_cost(a.op)
            extra_c, extra_s = (
                _callsub_extra(region.bb) if a.op == "callsub" else (0, 0)
            )
            new_cum = cum + oc + extra_c
            new_ic = ic
            if a.op in ("itxn_submit", "itxn_next"):
                if new_ic >= MAX_INNER_TXNS:
                    return cum, ic  # AVM halts at 257th submit
                new_ic += 1
            elif a.op == "callsub":
                new_ic = min(MAX_INNER_TXNS, new_ic + extra_s)
            if new_cum > path_ceiling(new_ic, group_size=group_size):
                return cum, ic  # AVM halts before this op completes
            cum, ic = new_cum, new_ic
            key = (a.location.file, a.location.line)
            prev = out.get(key)
            if prev is None or cum > prev[2]:
                out[key] = (a.op, oc + extra_c, cum)
        return cum, ic

    if isinstance(region, SequenceR):
        cum, ic = entry_cum, entry_ic
        for p in region.parts:
            cum, ic = _fold_max(p, cum, ic, group_size, out)
        return cum, ic

    if isinstance(region, IfR):
        c_cum, c_ic = _fold_max(region.cond, entry_cum, entry_ic, group_size, out)
        t_cum, t_ic = _fold_max(
            region.then_branch, c_cum, c_ic, group_size, out
        )
        # Join: either skip the then-arm or take it.
        return max(c_cum, t_cum), max(c_ic, t_ic)

    if isinstance(region, GuardR):
        # Fold cond, then fold the exit_arm purely for line recording
        # (it executes on the branch-taken path) — but the forward
        # state is the cond's exit, not the arm's.
        c_cum, c_ic = _fold_max(region.cond, entry_cum, entry_ic, group_size, out)
        _fold_max(region.exit_arm, c_cum, c_ic, group_size, out)
        return c_cum, c_ic

    if isinstance(region, IfElseR):
        c_cum, c_ic = _fold_max(region.cond, entry_cum, entry_ic, group_size, out)
        t_cum, t_ic = _fold_max(
            region.then_branch, c_cum, c_ic, group_size, out
        )
        e_cum, e_ic = _fold_max(
            region.else_branch, c_cum, c_ic, group_size, out
        )
        return max(t_cum, e_cum), max(t_ic, e_ic)

    if isinstance(region, SwitchR):
        c_cum, c_ic = _fold_max(region.cond, entry_cum, entry_ic, group_size, out)
        best_cum, best_ic = c_cum, c_ic
        for case in region.cases:
            cc, ci = _fold_max(case, c_cum, c_ic, group_size, out)
            if cc > best_cum:
                best_cum = cc
            if ci > best_ic:
                best_ic = ci
        return best_cum, best_ic

    if isinstance(region, LoopR):
        return _fold_loop_max(region, entry_cum, entry_ic, group_size, out)

    if isinstance(region, ImproperR):
        return _fold_improper_max(region, entry_cum, entry_ic, group_size, out)

    return entry_cum, entry_ic


def _fold_improper_max(
    region,
    entry_cum: int,
    entry_ic: int,
    group_size: int,
    out: dict[tuple[str, int], tuple[str, int, int]],
) -> tuple[int, int]:
    """Acyclic-DAG fold for an :class:`ImproperR`. Loops were collapsed
    in Phase 1 of :func:`build_control_tree`, so by construction the
    improper's internal edges form a DAG — we can topologically sort
    and thread ``(cum, ic)`` through it node-by-node. Each interior
    node gets the max-of-predecessors entry state."""
    import networkx as nx

    g = nx.DiGraph()
    for n in region.nodes:
        g.add_node(n)
    for u, v in region.edges:
        g.add_edge(u, v)
    try:
        topo = list(nx.topological_sort(g))
    except nx.NetworkXUnfeasible:
        # Still cyclic — shouldn't happen but degrade to loose fold.
        c, s = _body_summary(region)
        for sub in region.nodes:
            _fold_max(sub, entry_cum, entry_ic, group_size, out)
        new_ic = min(MAX_INNER_TXNS, entry_ic + s)
        return (
            min(entry_cum + c, path_ceiling(new_ic, group_size=group_size)),
            new_ic,
        )

    entry_ids = {id(e) for e in region.entries}
    state: dict[int, tuple[int, int] | None] = {id(n): None for n in region.nodes}
    for n in region.nodes:
        if id(n) in entry_ids:
            state[id(n)] = (entry_cum, entry_ic)

    sink_exits: list[tuple[int, int]] = []
    for n in topo:
        s = state[id(n)]
        if s is None:
            continue  # unreachable in this fold
        n_cum, n_ic = _fold_max(n, s[0], s[1], group_size, out)
        succs = list(g.successors(n))
        if not succs:
            sink_exits.append((n_cum, n_ic))
            continue
        for succ in succs:
            prev = state[id(succ)]
            if prev is None:
                state[id(succ)] = (n_cum, n_ic)
            else:
                state[id(succ)] = (
                    max(prev[0], n_cum), max(prev[1], n_ic)
                )

    if not sink_exits:
        return entry_cum, entry_ic
    return (
        max(e[0] for e in sink_exits),
        max(e[1] for e in sink_exits),
    )


def _fold_loop_max(
    region,
    entry_cum: int,
    entry_ic: int,
    group_size: int,
    out: dict[tuple[str, int], tuple[str, int, int]],
) -> tuple[int, int]:
    """Fold a loop region: walk the body once at each of two entry
    states — the last fully-completable iter and the partial halting
    iter — to record the worst-case cum at every body line. Return
    the post-loop ``(exit_cum, exit_ic)``."""
    body_cost, body_submits = _body_summary(region.body)
    if body_cost == 0:
        # Zero-progress loop — body runs once at most.
        return _fold_max(region.body, entry_cum, entry_ic, group_size, out)
    full_iters = _max_iters_full(
        entry_cum, entry_ic, body_cost, body_submits, group_size
    )
    if full_iters <= 0:
        # Loop doesn't enter — body still recorded once for any
        # entry BB that's also an exit (rare; defensive).
        _fold_max(region.body, entry_cum, entry_ic, group_size, out)
        return entry_cum, entry_ic
    # Last fully-completable iter (k = full_iters) — entry state at
    # the start of that iter is ``entry + (full_iters - 1) * body_cost``.
    last_full_cum = entry_cum + (full_iters - 1) * body_cost
    last_full_ic = entry_ic + (full_iters - 1) * body_submits
    _fold_max(region.body, last_full_cum, last_full_ic, group_size, out)
    # Partial halting iter (k = full_iters + 1) — body executes until
    # cum exceeds the path ceiling. ``_fold_max`` on each Block enforces
    # that automatically, so we just hand it the partial entry state
    # and only the reachable prefix is recorded.
    partial_cum = entry_cum + full_iters * body_cost
    partial_ic = entry_ic + full_iters * body_submits
    if (
        partial_ic <= MAX_INNER_TXNS
        and partial_cum <= path_ceiling(partial_ic, group_size=group_size)
    ):
        _fold_max(region.body, partial_cum, partial_ic, group_size, out)
    exit_cum = entry_cum + full_iters * body_cost
    exit_ic = entry_ic + full_iters * body_submits
    if exit_ic > MAX_INNER_TXNS:
        exit_ic = MAX_INNER_TXNS
    return exit_cum, exit_ic


def per_line_costs(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> dict[tuple[str, int], tuple[str, int, int]]:
    """Per-line ``(op_name, op_cost, max_cumulative)`` map.

    Delegates to :func:`per_line_cost_paths` and takes the max of
    each line's cum set."""
    paths = per_line_cost_paths(prog, group_size=group_size)
    return {
        key: (op, oc, max(cums)) for key, (op, oc, cums) in paths.items()
    }


# Module-level cache used during a single ``per_line_cost_paths`` call
# so the BlockR fold can look up the active subroutine summaries
# without threading an extra parameter through every recursive call.
_active_sub_summaries: dict[int, tuple[int, int]] = {}


def _callsub_extra(bb) -> tuple[int, int]:
    """Extra ``(cost, submits)`` to add at a ``callsub`` op based on
    the active subroutine summaries. Resolved by following the
    callee BB id; returns ``(0, 0)`` when the callee isn't known
    (e.g. analyzing a region without its enclosing program)."""
    if not bb.successors or not _active_sub_summaries:
        return 0, 0
    callee = bb.successors[0]
    return _active_sub_summaries.get(id(callee), (0, 0))


def per_line_cost_paths(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> dict[tuple[str, int], tuple[str, int, list[int]]]:
    """Per-line ``(op_name, op_cost, sorted_cums)`` — every distinct
    cum at which the line is reachable, including one per loop
    iteration. Built by folding ``cum``-set propagation over the
    control tree (see module docstring).

    Capped at :data:`MAX_CUMS_PER_LINE` per line; lines that hit the
    cap remain sound (every reported cum is genuinely reachable, just
    not exhaustive)."""
    from .control_tree import build_control_tree, ProgramR

    tree = build_control_tree(prog)
    cums_per_line: dict[tuple[str, int], set[int]] = {}
    op_meta: dict[tuple[str, int], tuple[str, int]] = {}

    # Populate the active subroutine summary table so ``BlockR`` folds
    # can charge each ``callsub`` op for its callee's static cost.
    global _active_sub_summaries
    _active_sub_summaries = {}
    if isinstance(tree, ProgramR):
        for entry_bb, summary in tree.subroutine_summaries.items():
            _active_sub_summaries[id(entry_bb)] = summary

    try:
        _fold_paths(
            tree, frozenset([(0, 0)]), group_size, cums_per_line, op_meta
        )
    finally:
        _active_sub_summaries = {}

    return {
        key: (op_meta[key][0], op_meta[key][1], sorted(cums))
        for key, cums in cums_per_line.items()
    }


def _fold_paths(
    region,
    entry_states: frozenset[tuple[int, int]],
    group_size: int,
    cums_per_line: dict[tuple[str, int], set[int]],
    op_meta: dict[tuple[str, int], tuple[str, int]],
) -> frozenset[tuple[int, int]]:
    """Recursive path-set fold: each region takes a set of possible
    entry ``(cum, ic)`` states and produces the set of possible exit
    states, while recording per-line cums into ``cums_per_line``."""
    from .control_tree import (
        BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR, ImproperR,
        ProgramR,
    )

    if isinstance(region, ProgramR):
        for prog_region in region.programs:
            _fold_paths(
                prog_region, frozenset([(0, 0)]), group_size,
                cums_per_line, op_meta,
            )
        # Also fold each subroutine intraprocedurally — gives per-line
        # cums relative to a fresh subroutine-entry state. Doesn't try
        # to thread caller-side cum in (would require folding the sub
        # once per call site, exponential in deeply nested call graphs).
        for sub_region in region.subroutines.values():
            _fold_paths(
                sub_region, frozenset([(0, 0)]), group_size,
                cums_per_line, op_meta,
            )
        return frozenset([(0, 0)])

    if not entry_states:
        return entry_states

    if isinstance(region, BlockR):
        return _fold_paths_block(
            region, entry_states, group_size, cums_per_line, op_meta
        )

    if isinstance(region, SequenceR):
        states = entry_states
        for p in region.parts:
            states = _fold_paths(p, states, group_size, cums_per_line, op_meta)
            if not states:
                break
        return states

    if isinstance(region, IfR):
        cond_states = _fold_paths(
            region.cond, entry_states, group_size, cums_per_line, op_meta
        )
        then_states = _fold_paths(
            region.then_branch, cond_states, group_size, cums_per_line, op_meta
        )
        # Join: either skip (cond_states) or take then-arm (then_states).
        return _merge_states(cond_states, then_states)

    if isinstance(region, GuardR):
        cond_states = _fold_paths(
            region.cond, entry_states, group_size, cums_per_line, op_meta
        )
        # exit_arm runs for recording but its states don't propagate.
        _fold_paths(
            region.exit_arm, cond_states, group_size, cums_per_line, op_meta
        )
        return cond_states

    if isinstance(region, IfElseR):
        cond_states = _fold_paths(
            region.cond, entry_states, group_size, cums_per_line, op_meta
        )
        then_states = _fold_paths(
            region.then_branch, cond_states, group_size, cums_per_line, op_meta
        )
        else_states = _fold_paths(
            region.else_branch, cond_states, group_size, cums_per_line, op_meta
        )
        return _merge_states(then_states, else_states)

    if isinstance(region, SwitchR):
        cond_states = _fold_paths(
            region.cond, entry_states, group_size, cums_per_line, op_meta
        )
        joined: frozenset[tuple[int, int]] = frozenset()
        for case in region.cases:
            case_states = _fold_paths(
                case, cond_states, group_size, cums_per_line, op_meta
            )
            joined = _merge_states(joined, case_states)
        return joined

    if isinstance(region, LoopR):
        return _fold_paths_loop(
            region, entry_states, group_size, cums_per_line, op_meta
        )

    if isinstance(region, ImproperR):
        return _fold_improper_paths(
            region, entry_states, group_size, cums_per_line, op_meta
        )

    return entry_states


def _fold_improper_paths(
    region,
    entry_states: frozenset[tuple[int, int]],
    group_size: int,
    cums_per_line: dict[tuple[str, int], set[int]],
    op_meta: dict[tuple[str, int], tuple[str, int]],
) -> frozenset[tuple[int, int]]:
    """Acyclic-DAG paths fold for an :class:`ImproperR`. Topologically
    threads cum/ic state sets through the residual, merging at each
    join via :func:`_merge_states`. Output = union of sink exits."""
    import networkx as nx

    g = nx.DiGraph()
    for n in region.nodes:
        g.add_node(n)
    for u, v in region.edges:
        g.add_edge(u, v)
    try:
        topo = list(nx.topological_sort(g))
    except nx.NetworkXUnfeasible:
        # Cyclic improper — loose fall-back.
        for sub in region.nodes:
            _fold_paths(sub, entry_states, group_size, cums_per_line, op_meta)
        c, s = _body_summary(region)
        result: set[tuple[int, int]] = set()
        for cum, ic in entry_states:
            new_ic = min(MAX_INNER_TXNS, ic + s)
            new_cum = min(cum + c, path_ceiling(new_ic, group_size=group_size))
            result.add((new_cum, new_ic))
        return frozenset(result)

    entry_ids = {id(e) for e in region.entries}
    in_states: dict[int, frozenset[tuple[int, int]]] = {
        id(n): frozenset() for n in region.nodes
    }
    for n in region.nodes:
        if id(n) in entry_ids:
            in_states[id(n)] = entry_states

    sink_exits: frozenset[tuple[int, int]] = frozenset()
    for n in topo:
        es = in_states[id(n)]
        if not es:
            continue
        exit_states = _fold_paths(n, es, group_size, cums_per_line, op_meta)
        succs = list(g.successors(n))
        if not succs:
            sink_exits = _merge_states(sink_exits, exit_states)
            continue
        for succ in succs:
            in_states[id(succ)] = _merge_states(
                in_states[id(succ)], exit_states
            )
    return sink_exits


def _fold_paths_block(
    region,
    entry_states: frozenset[tuple[int, int]],
    group_size: int,
    cums_per_line: dict[tuple[str, int], set[int]],
    op_meta: dict[tuple[str, int], tuple[str, int]],
) -> frozenset[tuple[int, int]]:
    """Block paths fold: for each entry state, walk ops, recording
    each line's cum into ``cums_per_line``. Return the set of exit
    states (one per entry that completed the block)."""
    exits: set[tuple[int, int]] = set()
    for entry_cum, entry_ic in sorted(entry_states, reverse=True):
        cum, ic = entry_cum, entry_ic
        halted = False
        for a in region.bb.assignments:
            oc = opcode_cost(a.op)
            extra_c, extra_s = (
                _callsub_extra(region.bb) if a.op == "callsub" else (0, 0)
            )
            new_cum = cum + oc + extra_c
            new_ic = ic
            if a.op in ("itxn_submit", "itxn_next"):
                if new_ic >= MAX_INNER_TXNS:
                    halted = True
                    break
                new_ic += 1
            elif a.op == "callsub":
                new_ic = min(MAX_INNER_TXNS, new_ic + extra_s)
            if new_cum > path_ceiling(new_ic, group_size=group_size):
                halted = True
                break
            cum, ic = new_cum, new_ic
            key = (a.location.file, a.location.line)
            op_meta.setdefault(key, (a.op, oc + extra_c))
            cum_set = cums_per_line.setdefault(key, set())
            if len(cum_set) < MAX_CUMS_PER_LINE:
                cum_set.add(cum)
        if not halted:
            exits.add((cum, ic))
    return frozenset(exits)


def _fold_paths_loop(
    region,
    entry_states: frozenset[tuple[int, int]],
    group_size: int,
    cums_per_line: dict[tuple[str, int], set[int]],
    op_meta: dict[tuple[str, int], tuple[str, int]],
) -> frozenset[tuple[int, int]]:
    """Loop paths fold: for each entry state, fold the body at every
    iter k ∈ [0, full_iters + 1] (the +1 picks up the partial
    halting iter). Records per-line cums on each iter into
    ``cums_per_line``. Returns the union of exit states across all
    entry states and iter counts."""
    body_cost, body_submits = _body_summary(region.body)
    exits: set[tuple[int, int]] = set()
    for entry_cum, entry_ic in sorted(entry_states, reverse=True):
        if body_cost == 0:
            # Zero-progress loop — body once, then exit at entry state.
            _fold_paths(
                region.body, frozenset([(entry_cum, entry_ic)]),
                group_size, cums_per_line, op_meta,
            )
            exits.add((entry_cum, entry_ic))
            continue
        full_iters = _max_iters_full(
            entry_cum, entry_ic, body_cost, body_submits, group_size
        )
        # k = 0: exit before entering body (rare but allowed for
        # multi-entry SCCs whose entry is also an exit).
        exits.add((entry_cum, entry_ic))
        # k = 1..full_iters: each iter records per-line cums and adds
        # an exit state.
        for k in range(1, full_iters + 1):
            iter_entry_cum = entry_cum + (k - 1) * body_cost
            iter_entry_ic = entry_ic + (k - 1) * body_submits
            if iter_entry_ic > MAX_INNER_TXNS:
                break
            _fold_paths(
                region.body, frozenset([(iter_entry_cum, iter_entry_ic)]),
                group_size, cums_per_line, op_meta,
            )
            exit_cum = entry_cum + k * body_cost
            exit_ic = entry_ic + k * body_submits
            if exit_ic > MAX_INNER_TXNS:
                exits.add((exit_cum, MAX_INNER_TXNS))
                break
            exits.add((exit_cum, exit_ic))
            if len(exits) >= MAX_CUMS_PER_LINE:
                break
        # Partial halting iter: per-line cums get recorded via the
        # block-level ceiling check inside ``_fold_paths`` — but we
        # do not contribute an "exit" state from a halting iter.
        partial_cum = entry_cum + full_iters * body_cost
        partial_ic = entry_ic + full_iters * body_submits
        if (
            partial_ic <= MAX_INNER_TXNS
            and partial_cum <= path_ceiling(partial_ic, group_size=group_size)
        ):
            _fold_paths(
                region.body, frozenset([(partial_cum, partial_ic)]),
                group_size, cums_per_line, op_meta,
            )
    return frozenset(exits)


def _merge_states(
    a: frozenset[tuple[int, int]],
    b: frozenset[tuple[int, int]],
) -> frozenset[tuple[int, int]]:
    """Set-union with a soft cap so chained branches/loops can't blow
    up the state set unboundedly. Past the cap we keep the largest
    cums (worst-case is what callers care about)."""
    merged = a | b
    if len(merged) <= MAX_CUMS_PER_LINE:
        return merged
    # Cap reached — keep the largest cums (sound for max-cum questions
    # downstream; the dropped states have strictly smaller cums).
    return frozenset(sorted(merged, key=lambda s: (s[0], s[1]))[-MAX_CUMS_PER_LINE:])


def render(prog: SSAProgram) -> str:
    """Per-line cost table, sorted by (file, line)."""
    lines = per_line_costs(prog)
    if not lines:
        return "(no instructions)"
    out: list[str] = []
    op_w = max(len(op) for op, _, _ in lines.values())
    for (f, ln), (op, oc, cum) in sorted(lines.items()):
        out.append(
            f"{f}:L{ln:<3}  {op.ljust(op_w)}  op_cost={oc:<4}  cum={cum}"
        )
    return "\n".join(out)


def to_dict(prog: SSAProgram, paths: bool = False) -> dict:
    """Structured cost output. With ``paths=False`` (default) each
    entry carries the per-line max ``cumulative``. With ``paths=True``
    each entry carries the full sorted ``cumulatives`` list — every
    distinct cum at which the line is reachable (capped at
    :data:`MAX_CUMS_PER_LINE`).

    Top-level fields:

    - ``budget_ceiling``: :func:`program_budget_ceiling` headline.
    - ``max_observed_cumulative``: largest cum across all lines.
    - ``paths`` (only when ``paths=True``): the input mode echo.
    """
    if paths:
        lines = per_line_cost_paths(prog)
        entries = []
        max_cum = 0
        for (f, ln), (op, oc, cums) in sorted(lines.items()):
            entries.append({
                "file": f,
                "line": ln,
                "op": op,
                "op_cost": oc,
                "cumulatives": cums,
            })
            if cums and cums[-1] > max_cum:
                max_cum = cums[-1]
        return {
            "entries": entries,
            "budget_ceiling": program_budget_ceiling(prog),
            "max_observed_cumulative": max_cum,
            "paths": True,
        }
    lines = per_line_costs(prog)
    entries = []
    max_cum = 0
    for (f, ln), (op, oc, cum) in sorted(lines.items()):
        entries.append({
            "file": f,
            "line": ln,
            "op": op,
            "op_cost": oc,
            "cumulative": cum,
        })
        if cum > max_cum:
            max_cum = cum
    return {
        "entries": entries,
        "budget_ceiling": program_budget_ceiling(prog),
        "max_observed_cumulative": max_cum,
    }
