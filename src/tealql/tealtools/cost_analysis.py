"""Per-line and per-path opcode cost analysis for TEAL programs.

Per line: ``op_cost`` (the instruction's own AVM budget cost) and ``cumulative``
(worst-case cost from entry, the max over CFG paths reaching it within budget).
Computed by a recursive fold over :mod:`.control_tree`'s typed region tree, so
nested loops count their inner contribution per outer iteration and branches
inside loops take the worst-case arm.

HAZARD: the whole module trades precision for SOUNDNESS in ONE direction —
reported cums OVER-approximate, so there are no false negatives for
budget-exhaustion findings. Two documented exceptions break that guarantee and
must be surfaced, not silently trusted:

* :data:`LENGTH_SCALED_OPS` and :data:`CURVE_SCALED_OPS` carry a representative
  BASE constant only, so they UNDER-count on large inputs / expensive curves.
  :func:`length_scaled_ops_used` names them; :func:`render` / :func:`to_dict`
  then report those lines as a lower bound.
* Box / state ops are charged 1, though the AVM scales box cost with size.

HAZARD: for lines INSIDE a subroutine, cums are relative to SUBROUTINE entry,
not program entry — each sub is folded once from a fresh ``(0, 0)`` state
(threading caller-side cum in would mean folding it per call site, exponential
on deep call graphs). A hot line in a sub called late in an expensive program
therefore reports a SMALL cumulative; the caller's share appears at its
``callsub`` line, which IS charged the callee's whole summary.

Other approximations, all over-approximate: every submitted inner txn is treated
as an appcall (only appcalls grant +700); ``ASSUMED_GROUP_SIZE`` is a flat
heuristic :mod:`.group_reasoning` can replace; per-iter cost is the longest
body-DAG path; an irreducible region with a residual cycle is bounded like a
loop. The cost table is intentionally partial — unlisted ops default to 1.
"""
from __future__ import annotations

from .ssa import BasicBlock, SSAProgram


# Crypto / EC / hash ops with non-default costs. HAZARD: this is AVM spec data —
# fixed-cost entries are pinned against puya's langspec by
# ``tests/test_cost_drift.py``. Variable-cost ops (puya models them as
# ``cost=None``) carry a representative constant and are listed below.
OPCODE_COSTS: dict[str, int] = {
    "sha256": 35,
    "keccak256": 130,
    "sha512_256": 45,
    "sha3_256": 130,
    "ed25519verify": 1900,
    "ed25519verify_bare": 1900,
    "falcon_verify": 1700,
    "ecdsa_verify": 1700,
    "ecdsa_pk_decompress": 650,
    "ecdsa_pk_recover": 2000,
    "vrf_verify": 5700,
    # Length-scaled: the AVM charges a base plus a per-input-chunk term, so no
    # constant is exact and only the BASE is charged here.
    "mimc": 10,             # + 550 per 32 bytes
    "sumhash512": 150,      # + 7  per 4 bytes
    "json_ref": 25,         # + 2  per 7 bytes
    "base64_decode": 1,     # + 1  per 16 bytes
    "ec_add": 13,
    "ec_scalar_mul": 970,
    "ec_pairing_check": 8700,
    "ec_multi_scalar_mul": 970,
    "ec_subgroup_check": 1850,
    "ec_map_to": 2300,
    "expw": 10,
    "bsqrt": 40,
    # `divw` is NOT here: the langspec prices it at the default 1.
    "divmodw": 20,
    "sqrt": 4,
    # 512-bit byte-math (fixed per-op costs, AVM v10).
    "b+": 10, "b-": 10,
    "b*": 20, "b/": 20, "b%": 20,
    "b|": 6, "b&": 6, "b^": 6, "b~": 4,
}
DEFAULT_COST = 1

#: Ops whose real AVM cost is ``OPCODE_COSTS[op] + k * ceil(len(input)/chunk)``.
#: HAZARD: :func:`opcode_cost` returns only the base, so a cum including one of
#: these is a LOWER bound, not the usual over-approximation.
LENGTH_SCALED_OPS: frozenset[str] = frozenset({
    "mimc", "sumhash512", "json_ref", "base64_decode",
})

#: Ops whose cost depends on the CURVE immediate; the table carries a
#: representative (not maximal) constant. Same caveat as above.
CURVE_SCALED_OPS: frozenset[str] = frozenset({
    "ec_add", "ec_scalar_mul", "ec_pairing_check", "ec_multi_scalar_mul",
    "ec_subgroup_check", "ec_map_to", "ecdsa_verify", "ecdsa_pk_decompress",
})


def length_scaled_ops_used(prog: SSAProgram) -> list[str]:
    """Sorted opcodes in ``prog`` whose modelled cost is NOT a sound upper bound.

    HAZARD: empty is the only case in which the reported cums are the documented
    worst-case over-approximation; non-empty means they may under-count."""
    inexact = LENGTH_SCALED_OPS | CURVE_SCALED_OPS
    return sorted({
        a.op for bb in prog.blocks.values() for a in bb.assignments
        if a.op in inexact
    })

# Absolute ceiling; the AVM halts long before this (~190k worst-case observed).
HARD_BUDGET_LIMIT = 200_000

# Budget per app-call txn — group peers and submitted inner appcalls each add
# this to the shared pool.
TXN_BUDGET = 700

# Assumed app-call peers in the group. The protocol max is 16; 4 fits typical
# groups and bounds tighter. Replace with a known size via ``group_reasoning``.
ASSUMED_GROUP_SIZE = 4

# AVM cap on inner txns one top-level call may submit. Bounds how far a loop
# emitting inner appcalls can extend its own budget: each grants +TXN_BUDGET,
# but only 256 times.
MAX_INNER_TXNS = 256

# Soft cap per line in :func:`per_line_cost_paths` — beyond it, keep min, max
# and a uniform sample, and flag the line truncated, so chained-loop
# multiplicative blowup can't dominate output size.
MAX_CUMS_PER_LINE = 10_000


def opcode_cost(op: str) -> int:
    """AVM opcode-budget cost for ``op``, defaulting to 1 for unlisted opcodes."""
    return OPCODE_COSTS.get(op, DEFAULT_COST)


def inner_txn_count(prog: SSAProgram) -> int:
    """Static upper bound on inner txns this program may submit — each
    ``itxn_submit`` ends one and each ``itxn_next`` ends one and starts another."""
    return sum(
        1
        for bb in prog.blocks.values()
        for a in bb.assignments
        if a.op in ("itxn_submit", "itxn_next")
    )


def path_ceiling(inner_count: int, group_size: int = ASSUMED_GROUP_SIZE) -> int:
    """Opcode budget left to a path that has already submitted ``inner_count``
    inner txns, capped by :data:`HARD_BUDGET_LIMIT`."""
    return min(
        HARD_BUDGET_LIMIT,
        TXN_BUDGET * group_size + TXN_BUDGET * inner_count,
    )


def _bb_in_cycle(bb: BasicBlock) -> bool:
    """True if ``bb`` can reach itself via the CFG."""
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
    """True iff any ``itxn_submit`` / ``itxn_next`` sits on a CFG cycle — if so
    it can grant +``TXN_BUDGET`` repeatedly, defeating the static-count bound."""
    for bb in prog.blocks.values():
        if any(a.op in ("itxn_submit", "itxn_next") for a in bb.assignments):
            if _bb_in_cycle(bb):
                return True
    return False


def program_budget_ceiling(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> int:
    """Sound upper bound on opcode budget for any execution.

    HAZARD: three tiers, always erring OVER. No submits at all: base group
    budget, tight. Submits but none on a CFG cycle: base + 700 each, tight —
    a cycle-free CFG can't revisit a submit. Submits ON a cycle:
    ``path_ceiling(MAX_INNER_TXNS)``, since the 256-submission protocol cap is
    then the only bound on how often the cycle re-grants +700 — loose but sound.
    """
    if _has_submit_in_cycle(prog):
        return path_ceiling(MAX_INNER_TXNS, group_size=group_size)
    return path_ceiling(inner_txn_count(prog), group_size=group_size)


def _max_iters_full(
    entry_cum: int,
    entry_ic: int,
    body_cost: int,
    submits_per_iter: int,
    group_size: int,
) -> int:
    """Max ``k`` full iterations that stay within budget and the inner-txn cap."""
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


def _body_summary(region, group_size: int = ASSUMED_GROUP_SIZE) -> tuple[int, int]:
    """Worst-case ``(per_iter_cost, per_iter_submits)`` for one execution of
    ``region``; a nested loop contributes ``max_iters × body_summary``.

    HAZARD: ``group_size`` must be the one the caller is analysing with — it
    sets the budget ceiling bounding nested-loop iteration counts, so the
    default would silently bound inner loops for a different group size."""
    from .control_tree import (
        BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR, ImproperR,
        ProgramR,
    )
    if isinstance(region, ProgramR):
        # Programs are independent; take the worst-case program's per-iter cost.
        c = max((_body_summary(p, group_size)[0] for p in region.programs), default=0)
        s = max((_body_summary(p, group_size)[1] for p in region.programs), default=0)
        return c, s
    if isinstance(region, BlockR):
        cost = 0
        subs = 0
        for a in region.bb.assignments:
            cost += opcode_cost(a.op)
            if a.op in ("itxn_submit", "itxn_next"):
                subs += 1
            elif a.op == "callsub":
                # HAZARD: charge the callee's whole static cost / submit count,
                # as the path fold does. Charging opcode_cost("callsub") == 1
                # with zero submits lets _max_iters_full over-estimate the
                # iteration count and UNDER-approximates the worst case.
                extra_c, extra_s = _callsub_extra(region.bb)
                cost += extra_c
                subs += extra_s
        return cost, subs
    if isinstance(region, SequenceR):
        c = s = 0
        for p in region.parts:
            pc, ps = _body_summary(p, group_size)
            c += pc
            s += ps
        return c, s
    if isinstance(region, IfR):
        cc, cs = _body_summary(region.cond, group_size)
        tc, ts = _body_summary(region.then_branch, group_size)
        # Worst case: take the then-arm.
        return cc + tc, cs + ts
    if isinstance(region, IfElseR):
        cc, cs = _body_summary(region.cond, group_size)
        tc, ts = _body_summary(region.then_branch, group_size)
        ec, es = _body_summary(region.else_branch, group_size)
        return cc + max(tc, ec), cs + max(ts, es)
    if isinstance(region, SwitchR):
        cc, cs = _body_summary(region.cond, group_size)
        if not region.cases:
            return cc, cs
        max_c = max(_body_summary(c, group_size)[0] for c in region.cases)
        max_s = max(_body_summary(c, group_size)[1] for c in region.cases)
        return cc + max_c, cs + max_s
    if isinstance(region, GuardR):
        # Worst case for completing the body is the guard NOT firing and control
        # falling through, so cost = cond only; exit_arm doesn't continue.
        return _body_summary(region.cond, group_size)
    if isinstance(region, LoopR):
        body_c, body_s = _body_summary(region.body, group_size)
        # Most permissive entry state (0, 0) → maximum iters → over-approximate
        # when this loop sits inside an outer body.
        iters = _max_iters_full(0, 0, body_c, body_s, group_size)
        return body_c * iters, body_s * iters
    if isinstance(region, ImproperR):
        # Each component executes at most once per PASS through the region;
        # nested loops were already expanded inside their LoopR summary.
        c = s = 0
        for n in region.nodes:
            nc, ns = _body_summary(n, group_size)
            c += nc
            s += ns
        # HAZARD: an improper region is IRREDUCIBLE, not necessarily acyclic —
        # it is exactly what build_control_tree could not collapse. With a
        # residual cycle it can run many passes, so it must be bounded like a
        # loop; summing one pass UNDER-approximates the worst case.
        if _improper_is_cyclic(region):
            iters = _max_iters_full(0, 0, c, s, group_size)
            return c * iters, s * iters
        return c, s
    return 0, 0


def _improper_is_cyclic(region) -> bool:
    """``True`` when an :class:`ImproperR`'s residual graph has a cycle."""
    import networkx as nx

    g = nx.DiGraph()
    g.add_nodes_from(id(n) for n in region.nodes)
    g.add_edges_from((id(u), id(v)) for u, v in region.edges)
    return not nx.is_directed_acyclic_graph(g)


def per_line_costs(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> dict[tuple[str, int], tuple[str, int, int]]:
    """Per-line ``(op_name, op_cost, max_cumulative)`` — the max of each line's cum set."""
    paths = per_line_cost_paths(prog, group_size=group_size)
    return {
        key: (op, oc, max(cums)) for key, (op, oc, cums) in paths.items()
    }


# Valid only during one ``per_line_cost_paths`` call, so the BlockR fold can
# reach the active subroutine summaries without threading a parameter through
# every recursive call.
_active_sub_summaries: dict[int, tuple[int, int]] = {}


def _callsub_extra(bb) -> tuple[int, int]:
    """Extra ``(cost, submits)`` for a ``callsub``, from the active subroutine
    summaries; ``(0, 0)`` when the callee is unknown (region analysed alone)."""
    if not bb.successors or not _active_sub_summaries:
        return 0, 0
    callee = bb.successors[0]
    return _active_sub_summaries.get(id(callee), (0, 0))


def per_line_cost_paths(
    prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE
) -> dict[tuple[str, int], tuple[str, int, list[int]]]:
    """Per-line ``(op_name, op_cost, sorted_cums)`` — every distinct cum at which
    the line is reachable, one per loop iteration included.

    Capped at :data:`MAX_CUMS_PER_LINE`; a capped line stays sound — every
    reported cum is genuinely reachable, just not exhaustive."""
    from .control_tree import build_control_tree, ProgramR

    tree = build_control_tree(prog)
    cums_per_line: dict[tuple[str, int], set[int]] = {}
    op_meta: dict[tuple[str, int], tuple[str, int]] = {}

    # So each ``callsub`` can be charged its callee's static cost.
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
    """Recursive fold: a region maps a set of entry ``(cum, ic)`` states to the
    set of exit states, recording per-line cums into ``cums_per_line``."""
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
        # Subroutines fold INTRAPROCEDURALLY, so their per-line cums are
        # relative to a fresh sub-entry state, not program entry.
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
        return _merge_states(cond_states, then_states, group_size)

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
        return _merge_states(then_states, else_states, group_size)

    if isinstance(region, SwitchR):
        cond_states = _fold_paths(
            region.cond, entry_states, group_size, cums_per_line, op_meta
        )
        joined: frozenset[tuple[int, int]] = frozenset()
        for case in region.cases:
            case_states = _fold_paths(
                case, cond_states, group_size, cums_per_line, op_meta
            )
            joined = _merge_states(joined, case_states, group_size)
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
    """Fold an :class:`ImproperR` by topologically threading state through the
    residual DAG, merging at joins; output is the union of sink exits."""
    import networkx as nx

    g = nx.DiGraph()
    for n in region.nodes:
        g.add_node(n)
    for u, v in region.edges:
        g.add_edge(u, v)
    try:
        topo = list(nx.topological_sort(g))
    except nx.NetworkXUnfeasible:
        # HAZARD: cyclic improper — many passes are possible, so bound it like a
        # loop; a single pass UNDER-approximates the worst case.
        for sub in region.nodes:
            _fold_paths(sub, entry_states, group_size, cums_per_line, op_meta)
        c, s = _body_summary(region, group_size)   # already iteration-bounded
        result: set[tuple[int, int]] = set()
        for cum, ic in entry_states:
            iters = _max_iters_full(cum, ic, c, s, group_size)
            new_ic = min(MAX_INNER_TXNS, ic + s * iters)
            new_cum = min(cum + c * iters,
                          path_ceiling(new_ic, group_size=group_size))
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
            sink_exits = _merge_states(sink_exits, exit_states, group_size)
            continue
        for succ in succs:
            in_states[id(succ)] = _merge_states(
                in_states[id(succ)], exit_states, group_size
            )
    return sink_exits


def _fold_paths_block(
    region,
    entry_states: frozenset[tuple[int, int]],
    group_size: int,
    cums_per_line: dict[tuple[str, int], set[int]],
    op_meta: dict[tuple[str, int], tuple[str, int]],
) -> frozenset[tuple[int, int]]:
    """Walk each entry state through the block's ops, recording per-line cums;
    returns one exit state per entry that completed the block."""
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
    """Fold the body at every iter ``k ∈ [0, full_iters + 1]`` per entry state
    (the ``+1`` picks up the partial halting iter), unioning the exit states."""
    body_cost, body_submits = _body_summary(region.body, group_size)
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
        # k = 0: exit before entering the body — allowed for a multi-entry SCC
        # whose entry is also an exit.
        exits.add((entry_cum, entry_ic))
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
        # Partial halting iter: its per-line cums are recorded by the
        # block-level ceiling check, but it contributes NO exit state.
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
    group_size: int = ASSUMED_GROUP_SIZE,
) -> frozenset[tuple[int, int]]:
    """Set-union with a soft cap so chained branches/loops can't blow up the
    state set.

    HAZARD: past the cap, rank by remaining HEADROOM
    (``path_ceiling(ic) - cum``), not by raw cum. A lower-cum state with a
    larger inner-txn count has a far higher ceiling and can accumulate much more
    downstream, so "keep the largest cums" drops the state that actually
    produces the worst case. Both extremes are force-kept."""
    merged = a | b
    if len(merged) <= MAX_CUMS_PER_LINE:
        return merged
    keep = set()
    by_cum = max(merged, key=lambda s: (s[0], s[1]))
    by_head = max(
        merged,
        key=lambda s: (path_ceiling(s[1], group_size=group_size) - s[0], s[1]),
    )
    keep.add(by_cum)
    keep.add(by_head)
    ranked = sorted(
        merged,
        key=lambda s: (path_ceiling(s[1], group_size=group_size) - s[0], s[0]),
        reverse=True,
    )
    for st in ranked:
        if len(keep) >= MAX_CUMS_PER_LINE:
            break
        keep.add(st)
    return frozenset(keep)


def render(prog: SSAProgram) -> str:
    """Per-line cost table sorted by ``(file, line)``, with a trailing note when
    the program uses an op whose modelled cost is not a sound upper bound."""
    lines = per_line_costs(prog)
    if not lines:
        return "(no instructions)"
    out: list[str] = []
    op_w = max(len(op) for op, _, _ in lines.values())
    for (f, ln), (op, oc, cum) in sorted(lines.items()):
        out.append(
            f"{f}:L{ln:<3}  {op.ljust(op_w)}  op_cost={oc:<4}  cum={cum}"
        )
    inexact = length_scaled_ops_used(prog)
    if inexact:
        out.append(
            f"\nNOTE: {', '.join(inexact)} cost more than the modelled constant "
            "(the AVM scales them by input length / curve), so these cums are a "
            "LOWER bound, not the usual worst-case over-approximation.")
    return "\n".join(out)


def to_dict(prog: SSAProgram, paths: bool = False) -> dict:
    """Structured cost output — per-line max ``cumulative``, or the full sorted
    ``cumulatives`` list with ``paths=True``, plus ``budget_ceiling``,
    ``max_observed_cumulative`` and ``inexact_cost_ops``.

    HAZARD: a non-empty ``inexact_cost_ops`` means the cums for lines using
    those ops are a LOWER bound, not the usual over-approximation."""
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
            "inexact_cost_ops": length_scaled_ops_used(prog),
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
        "inexact_cost_ops": length_scaled_ops_used(prog),
    }
