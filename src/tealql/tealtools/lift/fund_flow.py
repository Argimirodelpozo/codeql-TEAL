"""Attacker-controlled inner-transaction FUND-FLOW detector (IR layer).

Backs the ``tainted-fund-flow`` detector. Every user-input-tainted value
reaching a fund-flow inner-txn field -- Receiver / Amount / CloseRemainderTo and
their asset variants -- is a finding, annotated with the guards that dominate the
sink (asserts and forced branches, classified by whether they check the tainted
input or the ``Sender``) so an UNGUARDED flow stands out from an already-gated
one. Built on :func:`taint.user_input_taint` plus dominators over the lifted IR
CFG; guards are recognised intra-procedurally AND across ``callsub`` boundaries.
``param_derived`` marks only the residual unresolved case: a param feeds the
sink, nothing guards it, and the sub has no call sites to inspect.

The default detector requires this representation and reports incomplete
analysis when it cannot be built.

HAZARD: RekeyTo is deliberately NOT a fund field here -- an app/itxn RekeyTo is
self-inflicted, not a tainted-field vuln. Rekey is an lsig-only check; see
``avm.FUND_FIELDS`` and the lsig ``rekey-to`` detector.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import pre_ir
from .taint import (
    UNKNOWN_SOURCE,
    _intr,
    _invoke,
    _merge_unresolved,
    state_value_writers,
    user_input_taint,
)
from ..language.avm import FUND_FIELDS as _FUND_FIELDS, is_state_value_label
from ..analysis.guard_coverage import every
from ..cfg.dominance import iterative_dominators
from .guards import (
    _WALK_MAX_DEPTH as _WALK_MAX_DEPTH,
    Guard as Guard,
    _Definitions as _Definitions,
    _GuardDefinitions as _GuardDefinitions,
    _classify as _classify,
    _input_key as _input_key,
    _is_sender_op as _is_sender_op,
    _value_children as _value_children,
    _walk as _walk,
)
from .taint_flow import source_label as _source_label

_SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
_SEV_BY_RANK = {rank: sev for sev, rank in _SEV_ORDER.items()}


def state_value_severity(severity: str, sources) -> str:
    """One step below ``severity`` when EVERY source is a ``StateValue``: the
    attacker must first land a write in an earlier call, and the value is
    then visible on chain before it is used. Any direct input keeps the full
    severity; LOW is the floor."""
    if not sources or not all(is_state_value_label(x) for x in sources):
        return severity
    rank = _SEV_ORDER.get(severity)
    return severity if rank is None else _SEV_BY_RANK[max(rank - 1, 0)]

# --------------------------------------------------------------------------
# IR CFG + dominators (intra-subroutine)
# --------------------------------------------------------------------------


# The one canonical successor spelling — a local copy had already drifted
# (it kept Switch's shadowed-key duplicate arms, minting phantom predecessors
# that weaken every dominance fact computed here).
_succs = pre_ir.succ_ids


def _dominators(sub) -> dict:
    """``{block_id: dominators}`` for one subroutine.

    HAZARD: seed EVERY in-sub-preds-less block, not ``ids[0]``. ``sub.body`` is
    ordered by ``(file, first_line)``, so any sub holding a block emitted above
    its own label — a shared epilogue, a block branched back into — has a
    non-entry block first. ``iterative_dominators`` then leaves the real entry
    SATURATED (its own documented failure for an unreachable seed), which makes
    every block in the sub "dominate" every sink, so every assert anywhere in it
    reads as guarding — a false GUARDED that suppresses the finding outright.
    With several entries dominator sets only SHRINK, which is the safe
    direction; ``or ids[:1]`` keeps a fully-cyclic body from having no seed."""
    ids = [b.id for b in sub.body]
    if not ids:
        return {}
    succ = {b.id: _succs(b.terminator) for b in sub.body}
    preds: dict = {i: [] for i in ids}
    for i in ids:
        for s in succ[i]:
            if s in preds:
                preds[s].append(i)
    entries = [i for i in ids if not preds[i]] or ids[:1]
    return iterative_dominators(ids, entries, lambda i: preds[i])


def _post_dominators(sub) -> dict:
    """``{block_id: post-dominators}`` for one subroutine — dominators on the
    REVERSED CFG, seeded at the blocks that leave it.

    ``iterative_dominators`` is parameterised by its edge accessor, so this is
    the same fixpoint with successors for predecessors and exits for entries."""
    ids = [b.id for b in sub.body]
    if not ids:
        return {}
    live = set(ids)
    succ = {b.id: [s for s in _succs(b.terminator) if s in live] for b in sub.body}
    exits = [i for i in ids if not succ[i]] or ids[-1:]
    return iterative_dominators(ids, exits, lambda i: succ[i])


def _cfg_maps(lifter) -> tuple[dict, dict]:
    """Revision-by-shape cache for lifted intra-sub CFG analyses.

    Every sink family reads the same completed lift.  Recomputing dominators
    and post-dominators once per family made one audit run solve identical
    fixed points roughly ten times.  The compact shape key keeps hand-mutated
    pre-IR in tests honest: a changed block set or terminator edge misses the
    cache rather than returning stale control-flow facts.
    """
    shape = tuple(
        (
            id(sub),
            tuple((id(block), block.id, tuple(_succs(block.terminator)))
                  for block in sub.body),
        )
        for sub in lifter.subs
    )
    cached = getattr(lifter, "_fund_flow_cfg_maps", None)
    if cached is not None and cached[0] == shape:
        return cached[1], cached[2]
    dominators = {sub.id: _dominators(sub) for sub in lifter.subs}
    post_dominators = {sub.id: _post_dominators(sub) for sub in lifter.subs}
    lifter._fund_flow_cfg_maps = (shape, dominators, post_dominators)
    return dominators, post_dominators


def _value_maps(lifter) -> tuple:
    """The taint-INDEPENDENT def/guard maps every sink family shares, cached
    like :func:`_cfg_maps` — an audit calls one family after another on the
    same completed lift, and each used to rebuild all six maps in full.
    Results are READ-ONLY to callers. The key adds op identity to the CFG
    shape so hand-mutated pre-IR in tests misses the cache."""
    dom_by_sub, pdom_by_sub = _cfg_maps(lifter)
    vshape = tuple(
        (id(sub), tuple(id(o) for b in sub.body for o in b.ops))
        for sub in lifter.subs
    )
    cached = getattr(lifter, "_fund_flow_value_maps", None)
    if cached is not None and cached[0] == vshape:
        return (dom_by_sub, pdom_by_sub, *cached[1])
    def_of = _def_map(lifter)
    # Value edges the def-walk follows: a call result into the callee's returns,
    # plus a scratch round-trip back to what was stored (same map shape).
    inv_ret = _invoke_returns(lifter)
    inv_ret.update(_scratch_value_edges(lifter, dom_by_sub))
    callee_sender = _callee_sender_guards(lifter, def_of, dom_by_sub, inv_ret)
    payload = (def_of, inv_ret, callee_sender, _call_sites(lifter))
    lifter._fund_flow_value_maps = (vshape, payload)
    return (dom_by_sub, pdom_by_sub, *payload)


def _cached_entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret,
                         callee_sender=None):
    """`_entry_guards` (and the callee-side `_callee_param_guards`, which reads
    the same taint oracle) keyed on the taint map's IDENTITY: `user_input_taint`
    is itself cached, so the same dict recurs across sink families. The cache
    holds a strong reference and compares with ``is`` — a bare ``id()`` key
    can be reused after GC and would serve stale guards for a different
    taint view (the id()-reuse trap this repo has been bitten by before)."""
    cached = getattr(lifter, "_fund_flow_entry_guards", None)
    if cached is not None and cached[0] is taint:
        return cached[1]
    callee_pg = _callee_param_guards(lifter, def_of, dom_by_sub, inv_ret, taint)
    out = (*_entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret, callee_sender),
           callee_pg)
    lifter._fund_flow_entry_guards = (taint, out)
    return out


def _all_fail_blocks(by_id) -> set:
    """Blocks from which EVERY path ends in a failing exit (``err`` / ``exit
    0``), least fixpoint over the sub's own CFG. A ``retsub`` returns to the
    caller, a non-constant ``exit v`` may succeed: neither is failing."""
    def _fails(t) -> bool:
        return isinstance(t, pre_ir.Fail) or (
            isinstance(t, pre_ir.ProgramExit)
            and isinstance(t.result, pre_ir.UInt64Constant) and t.result.value == 0)

    fails = {i for i, b in by_id.items() if _fails(b.terminator)}
    changed = True
    while changed:
        changed = False
        for i, b in by_id.items():
            if i in fails:
                continue
            succ = [s for s in _succs(b.terminator) if s in by_id]
            if succ and all(s in fails for s in succ):
                fails.add(i)
                changed = True
    return fails


def _post_dominating_guards(by_id, pdom, sink_bid, sink_idx, def_of, sink_regs,
                            sink_keys, inv_ret=None, taint=None, fails=None, *,
                            classify=None) -> list:
    """Checks that MUST run after the sink, and therefore still gate it.

    A failed ``assert`` reverts the ENTIRE transaction, inner transactions
    included, so an assert the sink cannot avoid reaching undoes the submit just
    as surely as one that ran before it. `itxn_submit; ...; assert(sender ==
    creator)` is a guarded flow, and reading only dominators called it unguarded.

    Two more shapes reject the whole transaction just as an assert does, and
    were read as "no check": a post-dominating ``exit v`` with a NON-constant
    ``v`` is ``assert v; exit 1`` (the approval verdict IS the condition —
    `itxn_submit; Sender == creator; return`), and a conditional branch whose
    OTHER edge can reach only failing exits (``err`` / ``exit 0``, see
    :func:`_all_fail_blocks`) is forced: `bnz ok; err` after the submit leaves
    no successful path on which the condition was false.

    HAZARD: an ordinary post-sink branch proves nothing — the sink already
    executed, and the branch merely selects which path runs next. Only the
    all-paths-fail edge turns it into a guard. Post-dominance is intra-sub,
    which is sufficient: the sub must reach one of its own exits, and the check
    lies on every such path (``retsub`` returns to the caller and is not a
    program exit, so the exit set below is what makes the claim, not the
    terminator kind)."""
    classify = classify or _classify      # late-bound: mutation gates patch it
    guards = []
    for d in pdom.get(sink_bid, {sink_bid}):
        blk = by_id.get(d)
        if blk is None:
            continue
        ops = blk.ops if d != sink_bid else blk.ops[sink_idx + 1:]
        for o in ops:
            if isinstance(o, pre_ir.Assert):
                guards.append(classify("assert-after", None, o.condition, def_of,
                                        sink_regs, sink_keys, inv_ret, taint))
        t = blk.terminator
        if isinstance(t, pre_ir.ProgramExit) and isinstance(t.result, pre_ir.Register):
            guards.append(classify("exit-after", None, t.result, def_of,
                                    sink_regs, sink_keys, inv_ret, taint))
        elif isinstance(t, pre_ir.ConditionalBranch):
            if fails is None:
                fails = _all_fail_blocks(by_id)
            nz, z = t.non_zero in fails, t.zero in fails
            if nz != z:
                guards.append(classify("branch-after", "false" if nz else "true",
                                        t.condition, def_of, sink_regs, sink_keys,
                                        inv_ret, taint))
    return guards


def _dead_itxn_field_writes(sub) -> set:
    """``id(intrinsic)`` of every ``itxn_field`` write that is UNCONDITIONALLY
    overwritten before the inner transaction is submitted: a later write of the
    same field in the SAME block, with no ``itxn_begin``/``itxn_next``/
    ``itxn_submit`` or subroutine call (which may submit) in between. The AVM
    keeps the LAST value set, so the earlier write never reaches a submit and
    flagging it reported a flow that cannot occur. Straight-line only — a
    conditional overwrite on another path leaves the first write live."""
    dead: set = set()
    for b in sub.body:
        pending: dict = {}
        for o in b.ops:
            s = _intr(o)
            if s is None:
                if _invoke(o) is not None:
                    pending.clear()
                continue
            if s.op in ("itxn_begin", "itxn_next", "itxn_submit"):
                pending.clear()
            elif s.op == "itxn_field" and s.immediates:
                field = str(s.immediates[0]).strip()
                if field in pending:
                    dead.add(pending[field])
                pending[field] = id(s)
    return dead


def _call_sites(lifter) -> dict:
    """``{id(call_result_register): (callee_param_index_by_id, args)}`` — the
    frame a value walk enters when it descends through a call result into the
    callee's returned expression, so a callee PARAMETER met there continues
    into THIS site's argument (context-sensitive: merging every site's
    arguments would hand the sink leaves from unrelated calls)."""
    out: dict = {}
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            inv = _invoke(o)
            callee = lifter.name2sub.get(inv.target) if inv is not None else None
            if callee is None:
                continue
            pidx = {id(p.register): i for i, p in enumerate(callee.parameters)}
            for t in getattr(o, "targets", ()) or ():
                if isinstance(t, pre_ir.Register):
                    out[id(t)] = (pidx, list(inv.args))
    return out


def _site_arg(r, ctx, sites):
    """The call-site argument a callee param ``r`` stands for under ``ctx``
    (a tuple of call-result ids, innermost last), or ``None``."""
    if not ctx or sites is None:
        return None
    pidx, args = sites[ctx[-1]]
    j = pidx.get(id(r))
    return args[j] if j is not None and j < len(args) else None


_TREE_MAX_VISITS = 4096


def _value_tree(root, def_of, inv_ret, sites) -> list:
    """Context-sensitive ``(register, def_op)`` value walk: ``_walk(...,
    value_only=True)`` plus the frame rule of :func:`_call_sites` — a callee
    param reached through a returned expression continues into the site's own
    argument. `Amount = f(x) - y` with `f` returning `p0 * rate` has the
    leaves of `x`, not an unreachable `p0`."""
    out: list = []
    seen: set = set()
    stack = [(root, ())]
    while stack and len(seen) < _TREE_MAX_VISITS:
        r, ctx = stack.pop()
        if not isinstance(r, pre_ir.Register) or (id(r), ctx) in seen or len(ctx) > 8:
            continue
        seen.add((id(r), ctx))
        o = def_of.get(id(r))
        out.append((r, o))
        if o is None:
            a = _site_arg(r, ctx, sites)
            if a is not None:
                stack.append((a, ctx[:-1]))
            continue
        stack.extend((c, ctx) for c in _value_children(r, def_of, None))
        if inv_ret:
            inner = ctx + (id(r),) if sites is not None and id(r) in sites else ctx
            stack.extend((rv, inner) for rv in inv_ret.get(id(r), ()))
    return out


def _uncovered_leaves(root, def_of, inv_ret, taint, credited_regs, credited_keys,
                      params, sites=None) -> list:
    """The tainted LEAVES of ``root``'s value tree that no credited check
    covers, as ``(leaf_register, param_index_or_None)``.

    A leaf is where taint ENTERS the value: a source read, a parameter of
    THIS sub, a scratch load or call result the walk cannot see through — any
    tainted register with no tainted value-child. A check COVERS a leaf when
    every value path from the root down to it passes a credited register or a
    read of a credited input slot, i.e. the checked value is what the leaf
    flows through. `Amount = btoi(arg0) + btoi(arg1)` has two leaves; `assert(
    btoi(arg0) <= 100)` credits one path, and the other leaf — arg1 — is what
    the attacker still chooses. Guard credit is existential per guard;
    coverage is the universal condition the sink actually needs. The walk is
    context-sensitive through call results (:func:`_value_tree`): a callee
    param met in a returned expression is the site's argument, not a leaf.

    HAZARD: a source read is a leaf even when its INDEX is tainted
    (`txnas ApplicationArgs i`): pinning the index pins which slot is read,
    never the value found there."""
    out: list = []
    seen: set = set()
    stack = [(root, ())]
    while stack and len(seen) < _TREE_MAX_VISITS:
        r, ctx = stack.pop()
        if (not isinstance(r, pre_ir.Register) or (id(r), ctx) in seen
                or not taint.get(id(r)) or len(ctx) > 8):
            continue
        seen.add((id(r), ctx))
        if id(r) in credited_regs:
            continue
        o = def_of.get(id(r))
        src = _intr(o) if o is not None else None
        if src is not None:
            k = _input_key(src)
            if k is not None and k in credited_keys:
                continue
            if _source_label(src) is not None:
                out.append((r, params.get(id(r)) if not ctx else None))
                continue
        if o is None:
            a = _site_arg(r, ctx, sites)
            if a is not None:
                # This site's argument is what the param holds here; an
                # untainted argument contributes no attacker control on
                # this path (the param's taint came from another site).
                if isinstance(a, pre_ir.Register) and taint.get(id(a)):
                    stack.append((a, ctx[:-1]))
                continue
        kids = [(c, ctx) for c in _value_children(r, def_of, None) if taint.get(id(c))]
        if inv_ret:
            inner = ctx + (id(r),) if sites is not None and id(r) in sites else ctx
            kids += [(rv, inner) for rv in inv_ret.get(id(r), ())
                     if isinstance(rv, pre_ir.Register) and taint.get(id(rv))]
        # A leaf is where taint ENTERS: no tainted value-child at all, or a
        # source label its visible children do not carry (it arrived through
        # a channel this walk cannot follow — a may-store scratch load, a
        # summary-only call transfer). HAZARD: with "no tainted child" alone,
        # a register that ALSO gained a visible tainted child (a StateValue
        # operand) stopped being a leaf and its ApplicationArgs entry was
        # silently "covered" by checks on the new child.
        if not kids or (taint.get(id(r)) or frozenset()) - frozenset().union(
                *(taint.get(id(c)) or frozenset() for c, _ in kids)):
            out.append((r, params.get(id(r)) if not ctx else None))
        stack.extend(kids)
    return out


def _invoke_returns(lifter) -> dict:
    """Map the i-th result of each ``InvokeSubroutine`` to the i-th register
    returned by every ``SubroutineReturn`` in the callee, so a guard walk can
    descend into an asserted validation subroutine."""
    name2sub = {s.id: s for s in lifter.subs}
    out: dict = {}
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            inv = _invoke(o)
            if inv is None:
                continue
            callee = name2sub.get(inv.target)
            if callee is None:
                continue
            # A returned PARAMETER is the call site's own argument: `clamp(x)`
            # that asserts `p <= 100` and `retsub`s `p` hands back `x`. Routing
            # the edge to the argument (per site, exactly) lets the sink walk
            # continue into the caller's value, where the guards on `x` and
            # the callee-side transfer on this very call can credit it; the
            # bare param register has no definition and dead-ended the walk.
            param_arg = {id(p.register): i for i, p in enumerate(callee.parameters)}
            rets_by_pos: dict = defaultdict(list)
            ntargets = len(getattr(o, "targets", ()) or ())
            for cb in callee.body:
                t = cb.terminator
                if isinstance(t, pre_ir.SubroutineReturn):
                    for i, v in enumerate(t.result):
                        # EVERY arm, constants and unknowns included. The
                        # return set is a JOIN (one arm per `retsub` path), and
                        # `_classify` conjoins it: a `int 1; retsub` arm that
                        # was silently skipped here made the remaining
                        # `Sender == creator; retsub` arm read as the whole
                        # answer — the multi-return OR-bypass.
                        j = param_arg.get(id(v)) if isinstance(v, pre_ir.Register) else None
                        if j is not None and j < len(inv.args):
                            v = inv.args[j]
                        rets_by_pos[i].append(v)
                    for i in range(len(t.result), ntargets):
                        rets_by_pos[i].append(pre_ir.Undefined())   # short return: unknown arm
            for i, tgt in enumerate(getattr(o, "targets", ()) or ()):
                if isinstance(tgt, pre_ir.Register):
                    out[id(tgt)] = rets_by_pos.get(i, [])
    return out


class _ScratchScan:
    """Scratch stores/loads of a lift and the CLOBBER question the must-
    semantics round-trips rest on (see :func:`_scratch_value_edges`): can a
    store of ``slot`` — or a call into a sub that may (transitively) store it,
    this sub included — run between op ``s_idx`` of block ``s_bid`` and op
    ``idx`` of block ``bid``, the first dominating the second?

    ``dynamic``: some ``stores`` writes a slot off the STACK, which can target
    any slot and destroys the single-writer premise — nothing is provable."""

    def __init__(self, lifter):
        self.stores: dict = {}     # slot -> [(sub_id, block_id, op_index, register|None)]
        self.loads: list = []      # (slot, sub_id, block_id, op_index, result_register)
        self.dynamic = False
        for s in lifter.subs:
            for b in s.body:
                for idx, o in enumerate(b.ops):
                    intr = _intr(o)
                    if intr is None:
                        continue
                    # Check `stores` BEFORE the `immediates` guard: it takes its slot
                    # off the STACK so it has none, and behind that guard this
                    # bail-out is unreachable — a dynamic write would silently leave
                    # its slot looking single-writer.
                    if intr.op == "stores":
                        self.dynamic = True
                        return
                    if not intr.immediates:
                        continue
                    slot = str(intr.immediates[0])
                    if intr.op == "store":
                        val = intr.args[0] if intr.args else None
                        self.stores.setdefault(slot, []).append(
                            (s.id, b.id, idx,
                             val if isinstance(val, pre_ir.Register) else None))
                    elif (intr.op == "load" and isinstance(o, pre_ir.Assignment)
                            and o.targets and isinstance(o.targets[0], pre_ir.Register)):
                        self.loads.append((slot, s.id, b.id, idx, o.targets[0]))
        self.subs = {s.id: s for s in lifter.subs}
        self.callees: dict = {s.id: set() for s in lifter.subs}
        for s in lifter.subs:
            for b in s.body:
                for o in b.ops:
                    inv = _invoke(o)
                    if inv is not None:
                        self.callees[s.id].add(inv.target)

    def _reachable_subs(self, start) -> set:
        seen, stack = set(), [start]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(self.callees.get(n, ()))
        return seen

    def _call_may_write(self, inv, sub_id, slot) -> bool:
        """A call between the store and the load can clobber ``slot`` only if
        some sub the callee can reach (itself included) stores it — the load's
        own sub counts, since a recursive activation re-runs its stores."""
        writers = {st[0] for st in self.stores.get(slot, ())} | {sub_id}
        return bool(self._reachable_subs(inv.target) & writers)

    @staticmethod
    def _reach(by_id, starts, forward, avoid):
        """Blocks reachable from ``starts`` without entering ``avoid``."""
        edges: dict = {i: [] for i in by_id}
        for i, b in by_id.items():
            for t in _succs(b.terminator):
                if t in edges:
                    (edges[i] if forward else edges[t]).append(t if forward else i)
        seen: set = set()
        stack = [x for x in starts if x != avoid]
        while stack:
            n = stack.pop()
            if n in seen or n == avoid:
                continue
            seen.add(n)
            stack.extend(edges[n])
        return seen

    def clobbered(self, sub_id, s_bid, s_idx, bid, idx, slot) -> bool:
        """A store of ``slot`` or a subroutine call that may store it can run
        between op ``s_idx`` of ``s_bid`` and op ``idx`` of ``bid``."""
        by_id = {b.id: b for b in self.subs[sub_id].body}

        def _hit(ops) -> bool:
            for o in ops:
                inv = _invoke(o)
                if inv is not None and self._call_may_write(inv, sub_id, slot):
                    return True
                i = _intr(o)
                if (i is not None and i.op == "store" and i.immediates
                        and str(i.immediates[0]) == slot):
                    return True
            return False

        if s_bid == bid:
            return _hit(by_id[bid].ops[s_idx + 1:idx])
        fwd = self._reach(by_id, _succs(by_id[s_bid].terminator), True, s_bid)
        bwd = self._reach(by_id, [bid], False, s_bid)
        if _hit(by_id[s_bid].ops[s_idx + 1:]):
            return True
        for mid in (fwd & bwd) - {bid}:
            if _hit(by_id[mid].ops):
                return True
        # The load's block: ops before the load always run between; those
        # after it too when the block can reach itself without passing the
        # store (a loop re-executes the load after them).
        cyclic = bid in self._reach(by_id, _succs(by_id[bid].terminator), True, s_bid)
        return _hit(by_id[bid].ops if cyclic else by_id[bid].ops[:idx])


def _scratch_value_edges(lifter, dom_by_sub) -> dict:
    """``{id(load_result_register): [stored_register]}`` for scratch round-trips
    the value PROVABLY survives — the same map shape as :func:`_invoke_returns`,
    so it merges into that map and every ``_walk`` threading it gets the edge for
    free. Without it a guard whose RESULT is round-tripped (``==; store 0;
    load 0; assert``) reaches the IR as ``assert (load 0)``, the def-walk
    dead-ends, and a correctly-guarded contract reads as a finding.

    HAZARD: MUST-semantics. Relaxing any condition credits a guard that need not
    have run, suppressing a real flow. No dynamic ``stores`` anywhere (one can
    target any slot, destroying the single-writer premise); the store is in the
    SAME subroutine as the load and DOMINATES it; and it is the store that
    REACHES the load — no other ``store`` of the slot, and no call into a sub
    that can (transitively) store it — this sub recursively included — on any
    path from the store to the load. Scratch is global, so a second writer in
    a dead-end branch (`bz go; int 0; store 0; int 0; return`) used to
    disprove the round-trip program-wide; it cannot run between the store and
    the load, so it never reaches it."""
    scan = _ScratchScan(lifter)
    if scan.dynamic:
        return {}                                  # dynamic slot: prove nothing
    stores, loads = scan.stores, scan.loads
    _clobbered = scan.clobbered

    out: dict = {}
    for slot, sub_id, bid, idx, result in loads:
        dom = dom_by_sub.get(sub_id, {}).get(bid, ())
        cands = [st for st in stores.get(slot, ())
                 if st[0] == sub_id and ((st[1] == bid and st[2] < idx)
                                         or (st[1] != bid and st[1] in dom))]
        if len(cands) != 1:
            continue                               # no, or several, dominating stores
        s_sub, s_bid, s_idx, s_reg = cands[0]
        if s_reg is None or s_reg is result:
            continue
        if _clobbered(sub_id, s_bid, s_idx, bid, idx, slot):
            continue
        out[id(result)] = [s_reg]
    return out


def _def_map(lifter) -> dict:
    index = _GuardDefinitions if getattr(lifter, '_analysis_frozen', False) else _Definitions
    d = index(getattr(lifter, 'prog', None))
    for b in pre_ir.blocks(lifter.subs):
        for ph in b.phis:
            d[id(ph.register)] = ph
        for o in b.ops:
            for t in getattr(o, "targets", ()) or ():
                d[id(t)] = o
    return d


def authority_evidence(lifter):
    """Authority premises used by the cached guard analysis, including summaries."""
    cached = getattr(lifter, '_fund_flow_value_maps', None)
    definitions = cached[1][0] if cached is not None else None
    return tuple(sorted(getattr(definitions, 'authority_evidence', ()), key=repr))


def _ir_op_str(o) -> str:
    """One-line label for a lifted-IR op: ``op imm @Lline`` / ``callsub NAME`` / ``φ``."""
    s = _intr(o)
    if s is not None:
        imm = " ".join(str(i) for i in (s.immediates or []))
        ln = getattr(s, "line", 0)
        return f"{s.op}{(' ' + imm) if imm else ''}" + (f" @L{ln}" if ln else "")
    inv = _invoke(o)
    if inv is not None:
        return f"callsub {inv.target}"
    if isinstance(o, pre_ir.Phi):
        return "φ"
    return "copy" if isinstance(o, pre_ir.Assignment) else str(o)


def ir_taint_chain(lifter, register, view, *, max_hops: int = 40) -> list:
    """The taint road in lifted-IR ops, SOURCE-first: walk backward from
    ``register`` along the tainted arg (per ``view``, a
    :class:`byte_taint.IrByteTaint`), crossing at a subroutine PARAMETER to the
    caller's bound arg at each ``InvokeSubroutine`` site."""
    def_of = _def_map(lifter)
    param_args: dict = {}          # id(param register) -> [caller arg values]
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            inv = _invoke(o)
            if inv is None:
                continue
            callee = lifter.name2sub.get(inv.target)
            if callee is None:
                continue
            for i, p in enumerate(callee.parameters):
                if i < len(inv.args):
                    param_args.setdefault(id(p.register), []).append(inv.args[i])

    def _tainted(v):
        return isinstance(v, pre_ir.Register) and (
            bool(view.tainted_bytes(v)) or view.is_scalar_tainted(v))

    def _pick(values):
        """Follow a covered-tainted operand, else an UNCOVERED register -- the
        byte-taint view covers only ~90% of registers, so the road must run
        through the gaps rather than dead-end at them."""
        values = list(values)
        return (next((v for v in values if _tainted(v)), None)
                or next((v for v in values
                         if isinstance(v, pre_ir.Register) and not view.is_covered(v)), None))

    chain: list = []
    seen: set = set()
    cur = register
    while cur is not None and id(cur) not in seen and len(chain) < max_hops:
        seen.add(id(cur))
        o = def_of.get(id(cur))
        nxt = None
        if o is not None:
            chain.append(o)
            src = _intr(o)
            if src is not None:
                nxt = _pick(src.args)
            elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                nxt = _pick([o.source])
            elif isinstance(o, pre_ir.Phi):
                nxt = _pick([pa.value for pa in o.args])
        if nxt is None:               # a parameter: cross callsub to the caller arg
            nxt = _pick(param_args.get(id(cur), ()))
        cur = nxt
    chain.reverse()
    return chain


def ir_taint_road(lifter, register, view, *, sep: str = "  →  ") -> str:
    """:func:`ir_taint_chain` as one line of IR ops; ``(no tainted road)`` if none."""
    ops = ir_taint_chain(lifter, register, view)
    return sep.join(_ir_op_str(o) for o in ops) if ops else "(no tainted road)"


# --------------------------------------------------------------------------
# Guards + findings
# --------------------------------------------------------------------------


def _blocks_reaching(by_id, target) -> set:
    """Block ids that can reach ``target``, including ``target`` itself."""
    preds: dict = {i: [] for i in by_id}
    for i, b in by_id.items():
        for s in _succs(b.terminator):
            if s in preds:
                preds[s].append(i)
    seen = {target}
    stack = [target]
    while stack:
        n = stack.pop()
        for p in preds.get(n, ()):
            if p not in seen:
                seen.add(p)
                stack.append(p)
    return seen


def _dominating_guards(by_id, dom, sink_bid, sink_idx, def_of, sink_regs, sink_keys,
                       inv_ret=None, taint=None, *, classify=None) -> list:
    """What every dominating assert / forced branch guarantees at the sink, one
    ``classify(kind, polarity, condition, ...)`` result each — `_classify`'s
    Guard by default; a sink policy with its own question (the key-namespace
    facts of :mod:`.key_namespace`) reuses the SAME placement rules."""
    classify = classify or _classify      # late-bound: mutation gates patch it
    doms = dom.get(sink_bid, {sink_bid})
    guards = []
    reach_sink = None                       # lazily: blocks that can reach the sink
    for d in doms:
        blk = by_id.get(d)
        if blk is None:
            continue
        # Asserts that must pass before the sink: all of a strictly-dominating
        # block, or those before the sink op in the sink's own block.
        ops = blk.ops if d != sink_bid else blk.ops[:sink_idx]
        for o in ops:
            if isinstance(o, pre_ir.Assert):
                guards.append(classify("assert", None, o.condition, def_of,
                                        sink_regs, sink_keys, inv_ret, taint))
        # A conditional branch whose outcome is forced: exactly one successor
        # dominates the sink.
        # HAZARD: that is necessary but NOT sufficient. If the OTHER successor
        # can itself reach the sink (a loop/merge back), a path takes the branch
        # the other way and still arrives, so the condition does not hold there.
        # Credit only when the non-dominating EDGE cannot reach the sink at all.
        t = blk.terminator
        if isinstance(t, pre_ir.ConditionalBranch) and d != sink_bid:
            nz, z = t.non_zero in doms, t.zero in doms
            if nz != z:
                if reach_sink is None:
                    reach_sink = _blocks_reaching(by_id, sink_bid)
                other = t.zero if nz else t.non_zero
                if other not in reach_sink:
                    guards.append(classify("branch", "true" if nz else "false",
                                            t.condition, def_of, sink_regs, sink_keys,
                                            inv_ret, taint))
    return guards


def _without_input_credit(g: Guard) -> Guard:
    """``g`` with its input credit withdrawn: the sink has a tainted leaf the
    union of its guards does not cover, so no single guard's "checks the
    input" is a verdict. The sender credit (not about any value) stands."""
    if not g.checks_input:
        return g
    return Guard(g.kind, g.polarity, False, g.checks_sender,
                 tuple(e for e in g.evidence if 'sink input' not in e.scope))


@dataclass
class FundFlowFinding:
    field: str
    severity: str
    sources: frozenset
    sub_id: str
    line: int
    guards: list             # list[Guard]
    param_derived: bool      # sink value flows from a sub param (guard may be upstream)
    sink_reg: object = None  # the tainted operand register -> ir_taint_road witness
    #: ``{StateValue label: untrusted writer lines}`` for the state-value
    #: sources among ``sources`` (empty when there are none).
    state_writers: dict = None

    def sources_text(self) -> str:
        """``ApplicationArgs+StateValue:payee (writer unguarded at L21)``."""
        parts = []
        for src in sorted(self.sources):
            lines = (self.state_writers or {}).get(src)
            if lines:
                where = ",".join(f"L{n}" for n in lines)
                src = f"{src} (writer unguarded at {where})"
            parts.append(src)
        return "+".join(parts)

    @property
    def guarded(self) -> bool:
        return any(g.checks_input or g.checks_sender for g in self.guards)

    def pretty(self) -> str:
        gd = (", guarded by " + "; ".join(g.describe() for g in self.guards
                                          if g.checks_input or g.checks_sender)) \
            if self.guarded else \
            ("  [param-derived: guard may be in a caller]" if self.param_derived
             else "  ** UNGUARDED **")
        src = self.sources_text()
        return (f"[{self.severity}] itxn {self.field} <- {src}  "
                f"({self.sub_id} line {self.line}){gd}")

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "sources": sorted(self.sources),
            "subroutine": self.sub_id,
            "line": self.line,
            "guarded": self.guarded,
            "param_derived": self.param_derived,
            "guards": [g.describe() for g in self.guards],
        }


def _sender_guard_dominates(by_id, dom, bid, idx, def_of, inv_ret, name2sub,
                            callee_sender) -> bool:
    """A sender pin holds at op ``idx`` of block ``bid``: a dominating
    assert/forced branch classified `checks_sender` (empty match sets — the
    sender is not about any value), or a dominating call to a sub that pins
    the sender on every return (the ``self._check_owner()`` helper)."""
    if any(g.checks_sender for g in _dominating_guards(
            by_id, dom, bid, idx, def_of, set(), set(), inv_ret)):
        return True
    if not callee_sender:
        return False
    for cbid in dom.get(bid, {bid}):
        cblk = by_id.get(cbid)
        if cblk is None:
            continue
        for co in (cblk.ops if cbid != bid else cblk.ops[:idx]):
            inv = _invoke(co)
            callee = name2sub.get(inv.target) if inv else None
            if callee is not None and callee_sender.get(callee.id):
                return True
    return False


def _entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret=None,
                  callee_sender=None):
    """Interprocedural guard summary ``{sub.id: {param_idx: (checks_input,
    checks_sender)}}``, the set of subs that are called somewhere, and
    ``{sub.id: bool}`` — EVERY call site of the sub runs under a sender pin.

    HAZARD: param ``i`` of sub ``S`` is entry-guarded only if EVERY call site
    passing a TAINTED value for arg ``i`` dominates (or post-dominates — a
    failed check after the call still reverts the callee's submit) that call
    with checks COVERING every tainted leaf of that value, or the sender --
    AND-across-sites, because the guard must hold on every path in. A leaf
    that is one of the CALLER's own params is covered when that param is
    entry-guarded in turn: transitive, monotone fixpoint, so guards only grow.
    An untainted-passing site cannot expose the sink, so it does not constrain
    the summary.

    The per-SUB sender bit is the same fact with no argument attached: a
    ``proto 0 0`` helper that reads ``txna ApplicationArgs`` ITSELF has nothing
    the per-param map could key on, so the owner check in the dispatcher that
    dominates its only ``callsub`` was invisible to it (the PyTeal
    ``@Subroutine`` helper idiom). ALL sites count here, tainted-passing or not
    — the callee's own read is what exposes the sink — AND-across-sites,
    transitive through the caller's own bit, least fixpoint from ``False``."""
    subs = {s.id: s for s in lifter.subs}
    name2sub = {s.id: s for s in lifter.subs if not s.is_main}
    _, pdom_by_sub = _cfg_maps(lifter)
    # Per-call-site arg facts, computed once (only the transitive part changes
    # across iterations): (caller_id, tainted, needs, intra_sender,
    # [caller param indices the arg flows from]) — ``needs`` is the list of
    # caller-param indices whose entry guard must cover the leaves the site's
    # own checks leave uncovered, or ``None`` when a leaf is not a param at
    # all (then no caller guard can ever cover it).
    recs: dict = {sid: [] for sid in subs}
    site_sender: dict = {sid: [] for sid in subs}   # (caller_id, sender pinned here)
    for s in lifter.subs:
        dom, pdom, by_id = dom_by_sub[s.id], pdom_by_sub[s.id], {b.id: b for b in s.body}
        fails = _all_fail_blocks(by_id)
        cpidx = {id(p.register): i for i, p in enumerate(s.parameters)}
        for b in s.body:
            for idx, o in enumerate(b.ops):
                inv = _invoke(o)
                if inv is None or inv.target not in subs:
                    continue
                pinned = _sender_guard_dominates(
                    by_id, dom, b.id, idx, def_of, inv_ret, name2sub, callee_sender)
                if not pinned:
                    pinned = any(g.checks_sender for g in _post_dominating_guards(
                        by_id, pdom, b.id, idx, def_of, set(), set(), inv_ret, taint,
                        fails))
                site_sender[inv.target].append((s.id, pinned))
                facts = []
                for arg in inv.args:
                    # VALUE walk: what reaches the callee through `len(x)` is
                    # x's length, so a guard on x's value is not a guard on it
                    # and x's entry guard does not transfer.
                    walked = list(_walk(arg, def_of, value_only=True))
                    aregs = {id(r) for r, _ in walked}
                    tainted = any(r in taint for r in aregs)
                    if not tainted:
                        # The fixed point below excludes this site from every
                        # parameter obligation. No value guard is consumed.
                        facts.append((s.id, False, None, False, []))
                        continue
                    akeys = {k for _, oo in walked
                             if (k := _input_key(_intr(oo) if oo is not None else None)) is not None}
                    # Match guards against the TAINTED members only, exactly as
                    # the sink path narrows `sink_regs` to `guard_regs`. `aregs`
                    # is the arg's whole def-tree, so matching any member credits
                    # a check on a co-operand the attacker does not control: with
                    # `callsub pay(state_rate * btoi(arg))`,
                    # `assert(state_rate <= cap)` reads as "the argument is
                    # validated" while `arg` stays free. Same canonical
                    # `payout = shares * price` shape the sink path already
                    # refuses — this path just never applied the rule.
                    gregs = {r for r in aregs if taint.get(r)}
                    guards = _dominating_guards(by_id, dom, b.id, idx, def_of, gregs,
                                                akeys, inv_ret, taint)
                    guards += _post_dominating_guards(by_id, pdom, b.id, idx, def_of,
                                                      gregs, akeys, inv_ret, taint, fails)
                    credited_regs = set().union(*(g.regs for g in guards if g.checks_input))
                    credited_keys = set().union(*(g.keys for g in guards if g.checks_input))
                    # HAZARD: coverage, not existence. The site's checks must
                    # cover EVERY tainted leaf of the argument — validating
                    # `p0` and passing `p0 + p1` leaves `p1` free, and so does
                    # bounding `btoi(arg0)` and passing `btoi(arg0) +
                    # btoi(arg1)`. A leaf that is a caller param is covered
                    # by the caller's own entry guard (fixpoint below); any
                    # other uncovered leaf makes the site unguardable.
                    uncovered = _uncovered_leaves(arg, def_of, None, taint, credited_regs,
                                                  credited_keys, cpidx)
                    needs = None if any(pi is None for _, pi in uncovered) else \
                        sorted({pi for _, pi in uncovered})
                    facts.append((s.id, tainted, needs,
                                  any(g.checks_sender for g in guards),
                                  [cpidx[r] for r in aregs if r in cpidx]))
                recs[inv.target].append(facts)
    eg = {sid: {i: (False, False) for i in range(len(subs[sid].parameters))} for sid in subs}
    called = {tid for tid, sites in recs.items() if sites}
    changed = True
    while changed:
        changed = False
        for tid, sites in recs.items():
            for i in range(len(subs[tid].parameters)):
                all_ci = all_cs = True
                seen = False
                for facts in sites:
                    if i >= len(facts):
                        all_ci = all_cs = False
                        break
                    cid, tainted, needs, cs0, ks = facts[i]
                    if not tainted:
                        continue                  # safe site: doesn't constrain
                    seen = True
                    # Every leaf the site left uncovered must be a caller param
                    # guarded at the caller's entry; `needs is None` means some
                    # leaf never can be. An empty `needs` is full local
                    # coverage and carries the credit by itself.
                    all_ci &= needs is not None and all(eg[cid][k][0] for k in needs)
                    # HAZARD: ``ks`` lists EVERY caller-param in this argument's
                    # value tree, so a composite like ``p0 + p1`` lists both.
                    # Credit the transitive sender guard only when ALL are
                    # guarded at the caller's entry. Empty ``ks`` must carry no
                    # credit (``all(())`` is vacuously True), hence the explicit
                    # ``bool(ks)``.
                    all_cs &= cs0 or bool(ks) and all(eg[cid][k][1] for k in ks)
                new = (seen and all_ci, seen and all_cs)
                if new != eg[tid][i]:
                    eg[tid][i] = new
                    changed = True
    sub_sender = {sid: False for sid in subs}
    changed = True
    while changed:
        changed = False
        for tid, sites in site_sender.items():
            new = every(pinned or sub_sender[cid] for cid, pinned in sites)
            if new != sub_sender[tid]:
                sub_sender[tid] = new
                changed = True
    return eg, called, sub_sender


def _callee_param_guards(lifter, def_of, dom_by_sub, inv_ret=None, taint=None) -> dict:
    """``{sub.id: {param_idx: (checks_input, checks_sender)}}`` — guards a sub
    applies to a param INTERNALLY that hold on RETURN (they dominate every
    ``SubroutineReturn``, so a post-call use of the caller's argument is
    constrained).

    The callee-side complement of :func:`_entry_guards`, covering a helper that
    ``assert``s its own parameter and returns nothing. Runs through
    :func:`_classify` like every other guard, so it records WHAT the check tests
    rather than a bare "is asserted" — with ``taint`` as the oracle for the
    comparison's other operand, `assert(p0 <= p1)` with an attacker-fed `p1`
    at some site is no bound on `p0`."""
    out: dict = {}
    for s in lifter.subs:
        dom, by_id = dom_by_sub[s.id], {b.id: b for b in s.body}
        rets = [b for b in s.body
                if isinstance(b.terminator, pre_ir.SubroutineReturn)]
        pg: dict = {}
        for i, p in enumerate(s.parameters):
            preg = {id(p.register)}
            per_return = [_dominating_guards(by_id, dom, rb.id, len(rb.ops), def_of,
                                             preg, set(), inv_ret, taint) for rb in rets]
            # JOIN across returns (no returns -> unknown): the walker's rule.
            pg[i] = (every(any(g.checks_input for g in gs) for gs in per_return),
                     every(any(g.checks_sender for g in gs) for gs in per_return))
        out[s.id] = pg
    return out


def _callee_sender_guards(lifter, def_of, dom_by_sub, inv_ret=None) -> dict:
    """``{sub.id: bool}`` — the sub checks the SENDER on every path that returns.

    A sender check is not about any particular parameter, so it cannot be
    expressed in :func:`_callee_param_guards`' per-param map, and the sink path
    only consults that map inside ``for ai, arg in enumerate(inv.args)`` gated on
    the arg overlapping the sink. The canonical ``self._check_owner()`` helper —
    ``proto 0 0``, assert sender == creator, return — therefore has no argument
    to overlap and could never be credited, no matter how plainly it dominates
    the sink. Same for a helper whose args are unrelated to the sink's value.

    AND across returns: a helper that checks the sender on one path and falls
    through on another has not checked it."""
    out: dict = {}
    for s in lifter.subs:
        dom, by_id = dom_by_sub[s.id], {b.id: b for b in s.body}
        rets = [b for b in s.body
                if isinstance(b.terminator, pre_ir.SubroutineReturn)]
        # Empty match sets: `_classify` sets `checks_sender` from a sender
        # read under a pinning equality, with no reference to sink_regs.
        # JOIN across returns: every one (and at least one) pins.
        out[s.id] = every(
            any(g.checks_sender for g in _dominating_guards(
                by_id, dom, rb.id, len(rb.ops), def_of, set(), set(), inv_ret))
            for rb in rets)
    return out


def _tainted_sink_flows(lifter, sink_of, taint=None, trusted_args=frozenset(),
                        sender_only=False, *, merge_unresolved=True,
                        state_notes=True, sink_guards=None) -> list:
    """Core taint-to-sink engine: ``sink_of(intrinsic)`` yields ``(label,
    severity, value_args)`` per sink, ``value_args`` being the operands whose
    taint makes it a finding. Returns UNGUARDED-first findings with the full
    guard machinery -- intra- and interprocedural dominance,
    validation-subroutine descent, caller entry-guards, cross-contract
    ``trusted_args``.

    HAZARD: ``sender_only`` counts ONLY sender/creator guards toward
    ``guarded``. The byte-precise partial-fund-flow detector sets it because it
    drives the engine with a byte-interval taint map that has ALREADY cleared
    validated byte ranges -- an input-slot guard would double-count and
    reintroduce the slot-granular blind spot where a check of one sub-field
    guards a different, unchecked one.

    HAZARD: input credit is COVERAGE, not existence. Each guard reports which
    of the sink's registers/slots it constrains; the sink is input-guarded only
    when the union over its dominating, post-dominating, caller-entry and
    callee-transfer checks covers EVERY tainted leaf of its value
    (:func:`_uncovered_leaves`). Otherwise every input credit is withdrawn —
    `Amount = btoi(arg0) + btoi(arg1)` under `assert(btoi(arg0) <= 100)` is
    reported, because arg1 is what the attacker still chooses.

    ``sink_guards(lifter, maps)`` is a sink policy's own guard family: called
    once with the shared maps, it returns ``guards_for(sub, block, idx,
    intrinsic) -> [Guard]`` whose input credit joins the coverage check like
    any other (the state-write key namespace, :mod:`.key_namespace`)."""
    if taint is None:
        taint = user_input_taint(lifter, trusted_args)
    elif merge_unresolved:
        # A caller-supplied abstraction replaces the input source lattice, not
        # TOP. Preserve ``Undefined -> op -> register`` through custom views.
        taint = _merge_unresolved(lifter, taint)
    dom_by_sub, pdom_by_sub, def_of, inv_ret, callee_sender, sites = _value_maps(lifter)
    entry_guards, called, sub_sender, callee_pg = _cached_entry_guards(
        lifter, def_of, dom_by_sub, taint, inv_ret, callee_sender)
    extra = None
    if sink_guards is not None:
        extra = sink_guards(lifter, dict(
            def_of=def_of, inv_ret=inv_ret, sites=sites, taint=taint,
            dom_by_sub=dom_by_sub, pdom_by_sub=pdom_by_sub))
    findings: list = []
    for sub in lifter.subs:
        dom = dom_by_sub[sub.id]
        pdom = pdom_by_sub[sub.id]
        by_id = {b.id: b for b in sub.body}
        fails = _all_fail_blocks(by_id)
        dead = _dead_itxn_field_writes(sub)
        pidx = {id(p.register): i for i, p in enumerate(sub.parameters)}
        for b in sub.body:
            for idx, o in enumerate(b.ops):
                s = _intr(o)
                if s is None or id(s) in dead:
                    continue
                for label, severity, value_args in sink_of(s):
                    sources: set = set()
                    valreg = None
                    for a in value_args:
                        if isinstance(a, pre_ir.Register):
                            tt = taint.get(id(a), set())
                            if tt:
                                sources |= tt
                                valreg = a
                        elif isinstance(a, pre_ir.Undefined):
                            # The lift could not resolve this operand, so it
                            # cannot be shown clean either. Skipping the sink
                            # would report NOTHING for a value the attacker may
                            # well control — the silent direction. Report it
                            # with its own source label instead.
                            sources.add(UNKNOWN_SOURCE)
                    if not sources:
                        continue
                    if valreg is not None:
                        # VALUE walk (stops below `len`/`bitlen`/`bzero`): the
                        # registers a value is computed FROM, which is what a
                        # check must constrain to constrain it.
                        walked = _value_tree(valreg, def_of, inv_ret, sites)
                        sink_regs = {id(r) for r, _ in walked}
                        # HAZARD: only the TAINTED sub-terms may satisfy a value
                        # check. `sink_regs` is the sink operand's whole def-tree,
                        # so matching a guard against any member credits checks on
                        # co-operands the attacker does not control — with
                        # `Amount = state_rate * arg`, `assert(state_rate <= cap)`
                        # reads as "the input is validated" while `arg` stays
                        # free. The canonical `payout = shares * price` shape.
                        guard_regs = {r for r in sink_regs if taint.get(r)}
                        sink_keys = {k for _, oo in walked
                                     if (k := _input_key(_intr(oo) if oo is not None else None)) is not None}
                    else:
                        sink_regs, guard_regs, sink_keys = set(), set(), set()
                    guards = _dominating_guards(by_id, dom, b.id, idx, def_of, guard_regs,
                                                sink_keys, inv_ret, taint)
                    # A failed assert reverts the inner txn too, so one the sink
                    # cannot avoid reaching gates it as well.
                    guards += _post_dominating_guards(by_id, pdom, b.id, idx, def_of,
                                                      guard_regs, sink_keys, inv_ret, taint,
                                                      fails)
                    if extra is not None and valreg is not None:
                        guards += extra(sub, b, idx, s)
                    credited_regs = set().union(*(g.regs for g in guards if g.checks_input))
                    credited_keys = set().union(*(g.keys for g in guards if g.checks_input))
                    # Interprocedural: a value flowing from a caller-checked param.
                    feeding = {pidx[r] for r in sink_regs if r in pidx}
                    egp = entry_guards.get(sub.id, {})
                    caller_ci = {i for i in feeding if egp.get(i, (False, False))[0]}
                    if caller_ci:
                        guards.append(Guard("caller", None, True, False))
                    if any(egp.get(i, (False, False))[1] for i in feeding):
                        guards.append(Guard("caller", None, False, True))
                    # ... and the sender pin needs no feeding param at all: every
                    # path INTO this sub runs under one.
                    elif sub_sender.get(sub.id):
                        guards.append(Guard("caller", None, False, True))
                    # Interprocedural (callee-side): the sink value was passed to
                    # a helper that validates that param, on a call dominating
                    # the sink; transfer that guard to the caller's value.
                    for cbid in dom.get(b.id, {b.id}):
                        cblk = by_id.get(cbid)
                        if cblk is None:
                            continue
                        cops = cblk.ops if cbid != b.id else cblk.ops[:idx]
                        for co in cops:
                            inv = _invoke(co)
                            callee = lifter.name2sub.get(inv.target) if inv else None
                            if callee is None:
                                continue
                            # A sub that checks the SENDER on every return
                            # guards this sink by dominating it — no argument
                            # needs to reach the sink's value, and a `proto 0 0`
                            # owner-check has none to offer.
                            if callee_sender.get(callee.id):
                                guards.append(Guard("callee", None, False, True))
                            cpg = callee_pg.get(callee.id, {})
                            for ai, arg in enumerate(inv.args):
                                ci, cs = cpg.get(ai, (False, False))
                                if not (ci or cs):
                                    continue
                                # VALUE walk: the callee checked the param's
                                # VALUE, which is the argument's value — not
                                # what lies below a `len` in its def tree.
                                # `check32(len(arg))` validates a length.
                                aw = list(_walk(arg, def_of, value_only=True))
                                aregs = {id(r) for r, _ in aw}
                                akeys = {k for _, oo in aw
                                         if (k := _input_key(_intr(oo) if oo else None))
                                         is not None}
                                # `guard_regs`, not `sink_regs`: overlapping the
                                # sink's whole def-tree credits a callee that
                                # validated an UNTAINTED co-operand — the same
                                # narrowing the intra-procedural path applies.
                                if (aregs & guard_regs) or (akeys & sink_keys):
                                    if ci:
                                        guards.append(Guard("callee", None, True, False))
                                        credited_regs |= aregs
                                        credited_keys |= akeys
                                    if cs:
                                        guards.append(Guard("callee", None, False, True))
                    if sender_only:
                        # Byte-taint owns input validation (byte-precise); drop
                        # input-slot guards so only sender/creator checks clear.
                        guards = [g for g in guards if g.checks_sender]
                    elif any(g.checks_input for g in guards):
                        uncovered = _uncovered_leaves(valreg, def_of, inv_ret, taint,
                                                      credited_regs, credited_keys, pidx, sites)
                        if any(pi is None or pi not in caller_ci for _, pi in uncovered):
                            guards = [_without_input_credit(g) for g in guards]
                    guarded = any(g.checks_input or g.checks_sender for g in guards)
                    param_derived = bool(feeding) and not guarded and sub.id not in called
                    state_writers = {}
                    if state_notes and any(is_state_value_label(x) for x in sources):
                        writers_of = state_value_writers(lifter, trusted_args)
                        state_writers = {x: writers_of[x] for x in sources if x in writers_of}
                    findings.append(FundFlowFinding(
                        label, state_value_severity(severity, sources), frozenset(sources),
                        sub.id, s.line, guards, param_derived, valreg, state_writers))
    findings.sort(key=lambda f: (f.guarded, f.param_derived,
                                 -_SEV_ORDER[f.severity], f.sub_id, f.line))
    return findings


def _itxn_sink_of(fields):
    def sink_of(s):
        if s.op != "itxn_field" or not s.immediates:
            return ()
        field = str(s.immediates[0]).strip()
        if field not in fields:
            return ()
        return ((field, fields[field], s.args),)
    return sink_of


def tainted_itxn_flows(lifter, fields, taint=None, trusted_args=frozenset(),
                       sender_only=False) -> list:
    """User-input-tainted values reaching one of the inner-txn ``fields`` (a
    ``{field_name: severity}`` map) -- fund-flow, arbitrary inner appcall
    (ApplicationID), asset (XferAsset) and asset-admin (acfg roles)."""
    return _tainted_sink_flows(lifter, _itxn_sink_of(fields), taint, trusted_args,
                               sender_only)


def itxn_selector_lines_returned_to_sender(
    lifter, *, selector_field: str, receiver_field: str,
) -> set[int]:
    """Selector-field source lines in an inner transaction returned to Sender.

    This is representation evidence, not detector policy: group ``itxn_field``
    operations by their ``itxn_begin`` / ``itxn_next`` / ``itxn_submit``
    boundaries and use the lifted def graph to decide whether the paired receiver
    derives from the current transaction's Sender.  Keeping the correlation here
    avoids joining an interprocedural pre-IR finding back to a separate SSA scan
    by source line.
    """
    definitions = _def_map(lifter)
    dominators, _unused_post_dom = _cfg_maps(lifter)
    value_edges = _invoke_returns(lifter)
    value_edges.update(_scratch_value_edges(lifter, dominators))

    def from_sender(value) -> bool:
        if not isinstance(value, pre_ir.Register):
            return False
        for _register, operation in _walk(
            value, definitions, inv_ret=value_edges,
        ):
            source = _intr(operation) if operation is not None else None
            if source is not None and _is_sender_op(source):
                return True
        return False

    returned: set[int] = set()
    for group in _itxn_field_groups(lifter):
        if any(from_sender(v) for _line, args in group.get(receiver_field, ())
               for v in args):
            returned.update(line for line, _args in group.get(selector_field, ()))
    return returned


def _itxn_field_groups(lifter) -> list:
    """Per-sub ``itxn_field`` writes grouped by their ``itxn_begin`` /
    ``itxn_next`` / ``itxn_submit`` boundaries (source order): a list of
    ``{field: [(line, args), ...]}``, one per inner transaction."""
    groups: list = []
    for sub in lifter.subs:
        ordered = []
        for block_order, block in enumerate(sub.body):
            for op_order, operation in enumerate(block.ops):
                intrinsic = _intr(operation)
                if intrinsic is not None:
                    ordered.append((intrinsic.line, block_order, op_order, intrinsic))
        ordered.sort(key=lambda item: item[:3])
        current = None
        for _line, _block_order, _op_order, intrinsic in ordered:
            if intrinsic.op in {"itxn_begin", "itxn_next"}:
                current = {}
                groups.append(current)
                continue
            if intrinsic.op == "itxn_submit":
                current = None
                continue
            if intrinsic.op != "itxn_field" or current is None \
                    or not intrinsic.immediates:
                continue
            field = str(intrinsic.immediates[0]).strip()
            current.setdefault(field, []).append((intrinsic.line, intrinsic.args))
    return groups


def itxn_selector_lines_self_optin(lifter, *, selector_field: str = "XferAsset") -> set[int]:
    """Selector-field lines of inner ASSET OPT-INS: an axfer whose every
    ``AssetReceiver`` is ``global CurrentApplicationAddress``, whose every
    ``AssetAmount`` is the constant 0 (or unset), and which sets neither
    ``AssetCloseTo`` nor ``AssetSender``. Such a transfer moves nothing out of
    the app — naming the asset only opts the app in (its MBR is the app's own
    cost, already bounded by the protocol)."""
    definitions = _def_map(lifter)

    def resolve(value):
        for _ in range(16):
            operation = definitions.get(id(value)) if isinstance(value, pre_ir.Register) else None
            if isinstance(operation, pre_ir.Assignment) and _intr(operation) is None:
                value = operation.source
                continue
            return value, operation
        return value, None

    def is_app_address(value) -> bool:
        _value, operation = resolve(value)
        source = _intr(operation) if operation is not None else None
        return (source is not None and source.op == "global"
                and tuple(source.immediates or ()) == ("CurrentApplicationAddress",))

    def is_zero(value) -> bool:
        value, _operation = resolve(value)
        return isinstance(value, pre_ir.UInt64Constant) and value.value == 0

    out: set[int] = set()
    for group in _itxn_field_groups(lifter):
        receivers = [v for _line, args in group.get("AssetReceiver", ()) for v in args]
        if not receivers or not all(is_app_address(v) for v in receivers):
            continue
        amounts = [v for _line, args in group.get("AssetAmount", ()) for v in args]
        if not all(is_zero(v) for v in amounts):
            continue
        if group.get("AssetCloseTo") or group.get("AssetSender"):
            continue
        out.update(line for line, _args in group.get(selector_field, ()))
    return out


# Persistent-state-write ops -> the index of their KEY operand in the lifted
# Intrinsic's args. HAZARD: args are TOP-FIRST (arg[0] is the LAST value pushed),
# so these indices read backwards from TEAL source order. Only the KEY is flagged
# — it is the destination slot a tainted value lets the attacker choose, whereas
# storing user data in the VALUE is normal.
from ..language.effects import STATE_EFFECTS

_STATE_WRITE_KEY_IDX = {op: e.key_index for op, e in STATE_EFFECTS.items()}
_STATE_WRITE_SEV = {op: e.severity.upper() for op, e in STATE_EFFECTS.items()}


def _state_write_sink_of(s):
    ki = _STATE_WRITE_KEY_IDX.get(s.op)
    if ki is None or ki >= len(s.args):
        return ()
    return ((s.op, _STATE_WRITE_SEV.get(s.op, "HIGH"), [s.args[ki]]),)


def tainted_state_writes(lifter, taint=None, trusted_args=frozenset()) -> list:
    """Tainted-KEY persistent state writes -- a user-input value reaching the KEY
    of a global/local/box write, delete, create or resize lets the attacker target
    an arbitrary slot: overwrite or erase owner/admin state, collide with or
    destroy a sensitive box. (A key derived from ``txn Sender`` -- the ubiquitous
    per-caller ``box[Sender]`` -- is not a taint source, so it never surfaces.)"""
    return _tainted_sink_flows(lifter, _state_write_sink_of, taint, trusted_args,
                               sink_guards=_key_namespace_guards)


def _key_namespace_guards(lifter, maps):
    """The state-write key's NAMESPACE confinement (:mod:`.key_namespace`):
    a prefix exclusion the write cannot avoid, whose namespace holds every
    slot the program reads with a key it chose itself."""
    from .key_namespace import KeyNamespaces
    return KeyNamespaces(lifter, maps["def_of"], maps["inv_ret"], maps["sites"],
                         maps["taint"], maps["dom_by_sub"], maps["pdom_by_sub"],
                         _dominating_guards, _post_dominating_guards,
                         _all_fail_blocks).sink_guards


def _log_sink_of(s):
    if s.op != "log" or not s.args:
        return ()
    return (("log", "LOW", s.args),)


def tainted_logs(lifter, taint=None, trusted_args=frozenset()) -> list:
    """User-input-tainted values emitted via ``log`` -- forged data for anything
    that trusts them: a CALLER reading its ``LastLog`` (itself a taint source), or
    an off-chain indexer. Output-integrity only, hence LOW severity."""
    return _tainted_sink_flows(lifter, _log_sink_of, taint, trusted_args)


def tainted_fund_flows(lifter, taint=None, trusted_args=frozenset(),
                       sender_only=False) -> list:
    """Fund-flow specialisation of :func:`tainted_itxn_flows`: tainted values
    reaching Receiver / Amount / CloseRemainderTo and their asset variants."""
    return tainted_itxn_flows(lifter, _FUND_FIELDS, taint, trusted_args, sender_only)


def fund_flow_report(lifter, name: str = "<program>") -> str:
    findings = tainted_fund_flows(lifter)
    out = [f"attacker-controlled inner-transaction fund flows  --  {name}",
           "=" * 72]
    if not findings:
        out.append("(no user-input-tainted fund-flow itxn fields)")
        return "\n".join(out)
    unguarded = [f for f in findings if not f.guarded and not f.param_derived]
    out.append(f"{len(findings)} tainted fund-flow sink(s); "
               f"{len(unguarded)} UNGUARDED")
    out.append("")
    for f in findings:
        out.append("  " + f.pretty())
    return "\n".join(out)


if __name__ == "__main__":
    import sys

    from ..ssa import SSAProgram
    from .lift import _Lifter
    for _src in [a for a in sys.argv[1:] if not a.startswith("-")]:
        _lf = _Lifter(SSAProgram(_src))
        _lf.build()
        _nm = _src.rstrip("/").rsplit("/", 1)[-1]
        print(fund_flow_report(_lf, _nm))
