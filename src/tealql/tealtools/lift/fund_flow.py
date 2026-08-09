"""Attacker-controlled inner-transaction FUND-FLOW detector (IR layer).

Backs the ``ir-tainted-fund-flow`` detector. Every user-input-tainted value
reaching a fund-flow inner-txn field -- Receiver / Amount / CloseRemainderTo and
their asset variants -- is a finding, annotated with the guards that dominate the
sink (asserts and forced branches, classified by whether they check the tainted
input or the ``Sender``) so an UNGUARDED flow stands out from an already-gated
one. Built on :func:`taint.user_input_taint` plus dominators over the lifted IR
CFG; guards are recognised intra-procedurally AND across ``callsub`` boundaries.
``param_derived`` marks only the residual unresolved case: a param feeds the
sink, nothing guards it, and the sub has no call sites to inspect.

Supersedes the SSA-layer ``tainted-fund-flow`` sibling, which survives only as
the automatic fallback when a contract fails to lift.

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
    source_label,
    user_input_taint,
)
from ..avm import FUND_FIELDS as _FUND_FIELDS
from ..cfg.dominance import iterative_dominators

_SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

#: Reads of the CURRENT transaction's Sender. HAZARD: the ``gtxn*`` family is
#: DELIBERATELY excluded -- whoever composes the group chooses `gtxn 1 Sender`,
#: so counting it as authorisation lets an attacker-satisfiable condition
#: suppress a real fund flow. Only the current txn's sender and the immutable
#: creator are sound authorisation signals.
_TXN_SENDER_FAM = frozenset({"txn", "txna"})

#: Ops whose result depends on the LENGTH, not the VALUE, of their operand: a
#: guard reaching an input only through these bounds its length, not its value
#: (see :func:`_classify`).
_VALUE_OPAQUE_OPS = frozenset({"len", "bitlen", "bzero"})

#: Equality / inequality comparisons, uint64 and bytes. Which one encloses a
#: sender read decides whether that read PINS the sender or merely excludes one
#: address -- see the comparison-sense reasoning in :func:`_classify`.
_EQ_OPS = frozenset({"==", "b=="})
_NEQ_OPS = frozenset({"!=", "b!="})
_CMP_OPS = _EQ_OPS | _NEQ_OPS | frozenset({
    "<", "<=", ">", ">=", "b<", "b<=", "b>", "b>=",
})


# --------------------------------------------------------------------------
# IR CFG + dominators (intra-subroutine)
# --------------------------------------------------------------------------


def _succs(term) -> list:
    if isinstance(term, pre_ir.Goto):
        return [term.target]
    if isinstance(term, pre_ir.ConditionalBranch):
        return [term.non_zero, term.zero]
    if isinstance(term, pre_ir.GotoNth):
        return list(term.blocks) + [term.default]
    if isinstance(term, pre_ir.Switch):
        return [b for _, b in term.cases] + [term.default]
    return []


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


def _post_dominating_guards(by_id, pdom, sink_bid, sink_idx, def_of, sink_regs,
                            sink_keys, inv_ret=None) -> list:
    """Asserts that MUST run after the sink, and therefore still gate it.

    A failed ``assert`` reverts the ENTIRE transaction, inner transactions
    included, so an assert the sink cannot avoid reaching undoes the submit just
    as surely as one that ran before it. `itxn_submit; ...; assert(sender ==
    creator)` is a guarded flow, and reading only dominators called it unguarded.

    ASSERTS ONLY, deliberately. A forced branch is credited pre-sink because
    reaching the sink PROVES the condition held; after the sink it proves
    nothing — the sink already executed, and the branch merely selects which
    path runs next. Post-dominance is also intra-sub, which is sufficient: the
    sub must reach one of its own exits, and the assert lies on every such path
    (``retsub`` returns to the caller and is not a program exit, so the exit set
    below is what makes the claim, not the terminator kind)."""
    guards = []
    for d in pdom.get(sink_bid, {sink_bid}):
        blk = by_id.get(d)
        if blk is None:
            continue
        ops = blk.ops if d != sink_bid else blk.ops[sink_idx + 1:]
        for o in ops:
            if isinstance(o, pre_ir.Assert):
                guards.append(_classify("assert-after", None, o.condition, def_of,
                                        sink_regs, sink_keys, inv_ret))
    return guards


# --------------------------------------------------------------------------
# Expression walk: registers + their defining ops behind a Value
# --------------------------------------------------------------------------


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
            rets_by_pos: dict = defaultdict(list)
            for cb in callee.body:
                t = cb.terminator
                if isinstance(t, pre_ir.SubroutineReturn):
                    for i, v in enumerate(t.result):
                        if isinstance(v, pre_ir.Register):
                            rets_by_pos[i].append(v)
            for i, tgt in enumerate(getattr(o, "targets", ()) or ()):
                if isinstance(tgt, pre_ir.Register):
                    out[id(tgt)] = rets_by_pos.get(i, [])
    return out


#: Depth bound on :func:`_walk`; the def-expression tree is unbounded in principle.
_WALK_MAX_DEPTH = 8


def _walk(value, def_of, depth=0, seen=None, inv_ret=None):
    """Yield ``(register, defining_op_or_None)`` for every register in the bounded
    def-expression tree behind ``value``, descending through a call result into
    the callee's returned values when ``inv_ret`` is given.

    HAZARD: ``seen`` maps ``id(register) -> shallowest depth expanded at``, NOT a
    plain visited set. With a set, a register first reached near the depth limit
    is expanded on a starved budget then permanently suppressed, so reaching it
    shallowly later skips its subtree -- which guards the walk finds becomes
    traversal-order dependent. Re-expanding on a strictly shallower reach still
    terminates: depth is bounded, so each register expands at most
    ``_WALK_MAX_DEPTH + 1`` times, and callers collect into sets."""
    if seen is None:
        seen = {}
    if not isinstance(value, pre_ir.Register) or depth > _WALK_MAX_DEPTH:
        return
    previous = seen.get(id(value))
    if previous is not None and previous <= depth:
        return
    seen[id(value)] = depth
    o = def_of.get(id(value))
    yield value, o
    if o is not None:
        src = _intr(o)
        if src is not None:
            for a in src.args:
                yield from _walk(a, def_of, depth + 1, seen, inv_ret)
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            yield from _walk(o.source, def_of, depth + 1, seen, inv_ret)
        elif isinstance(o, pre_ir.Phi):
            for pa in o.args:
                yield from _walk(pa.value, def_of, depth + 1, seen, inv_ret)
    if inv_ret:                       # descend into an asserted validation sub
        for rv in inv_ret.get(id(value), ()):
            yield from _walk(rv, def_of, depth + 1, seen, inv_ret)


def _is_sender_op(src) -> bool:
    if not isinstance(src, pre_ir.Intrinsic):
        return False
    imm = " ".join(str(i) for i in (src.immediates or []))
    return src.op in _TXN_SENDER_FAM and (
        "Sender" in imm
        or (src.op == "txna" and imm.split() == ["Accounts", "0"])
    )


def _scratch_value_edges(lifter, dom_by_sub) -> dict:
    """``{id(load_result_register): [stored_register]}`` for scratch round-trips
    the value PROVABLY survives — the same map shape as :func:`_invoke_returns`,
    so it merges into that map and every ``_walk`` threading it gets the edge for
    free. Without it a guard whose RESULT is round-tripped (``==; store 0;
    load 0; assert``) reaches the IR as ``assert (load 0)``, the def-walk
    dead-ends, and a correctly-guarded contract reads as a finding.

    HAZARD: MUST-semantics. Relaxing any condition credits a guard that need not
    have run, suppressing a real flow. No dynamic ``stores`` anywhere (one can
    target any slot, destroying the single-writer premise); EXACTLY ONE ``store``
    for the slot PROGRAM-WIDE (scratch is global, so the count cannot be
    per-sub); and that store in the SAME subroutine as the load, dominating it."""
    stores: dict = {}          # slot -> [(sub_id, block_id, op_index, register|None)]
    loads: list = []           # (slot, sub_id, block_id, op_index, result_register)
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
                    return {}                      # dynamic slot: prove nothing
                if not intr.immediates:
                    continue
                slot = str(intr.immediates[0])
                if intr.op == "store":
                    val = intr.args[0] if intr.args else None
                    stores.setdefault(slot, []).append(
                        (s.id, b.id, idx,
                         val if isinstance(val, pre_ir.Register) else None))
                elif (intr.op == "load" and isinstance(o, pre_ir.Assignment)
                        and o.targets and isinstance(o.targets[0], pre_ir.Register)):
                    loads.append((slot, s.id, b.id, idx, o.targets[0]))

    out: dict = {}
    for slot, sub_id, bid, idx, result in loads:
        st = stores.get(slot) or []
        if len(st) != 1:
            continue                               # 0 or several writers: unprovable
        s_sub, s_bid, s_idx, s_reg = st[0]
        if s_reg is None or s_sub != sub_id or s_reg is result:
            continue
        if s_bid == bid:
            if s_idx >= idx:
                continue                           # store is not before the load
        elif s_bid not in dom_by_sub.get(sub_id, {}).get(bid, ()):
            continue                               # store does not dominate the load
        out[id(result)] = [s_reg]
    return out


def _def_map(lifter) -> dict:
    d: dict = {}
    for b in pre_ir.blocks(lifter.subs):
        for ph in b.phis:
            d[id(ph.register)] = ph
        for o in b.ops:
            for t in getattr(o, "targets", ()) or ():
                d[id(t)] = o
    return d


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


@dataclass
class Guard:
    kind: str                 # "assert" | "branch"
    polarity: str | None      # "true" / "false" for a branch, else None
    checks_input: bool        # the condition tests the (same-source) tainted input
    checks_sender: bool       # the condition tests txn Sender / Global.CreatorAddress

    def describe(self) -> str:
        tags = []
        if self.checks_sender:
            tags.append("sender")
        if self.checks_input:
            tags.append("tainted-input")
        p = f"({self.polarity})" if self.polarity else ""
        return f"{self.kind}{p}:{'+'.join(tags) or 'other'}"


def _input_key(src):
    """Identity of a specific user-input READ, e.g. ``("txn", ("ApplicationArgs",
    "0"))``, so two reads of the SAME slot match but ApplicationArgs[0] vs [1]
    don't; ``None`` if ``src`` isn't a user-input source op."""
    if src is None or source_label(src) is None:
        return None
    # HAZARD: dynamic-index reads carry the array INDEX on the stack, not in
    # immediates, so two DIFFERENT-index reads share one (op, immediates) key and
    # would collapse -- a guard on arg[0] crediting a use of arg[1]. Return None
    # so they fall back to register-identity matching.
    if src.op in ("txnas", "gtxnas", "gtxnsas", "gloadss"):
        return None
    return (src.op, tuple(str(i) for i in (src.immediates or [])))


def _classify(kind, polarity, cond, def_of, sink_regs, sink_keys, inv_ret=None) -> Guard:
    # HAZARD: guard-classification soundness. Every rule below exists because
    # crediting a check that does not actually constrain the sink's value
    # suppresses a real, exploitable flow.
    #
    # VALUE-level, not source-FAMILY-level: the guard must test the SAME value the
    # sink uses -- a shared register in their def-trees, or a read of the same
    # specific input slot. Family-level overlap (any ApplicationArgs read) would
    # read "validates SOME input" as "validates THIS value".
    #
    # BOOLEAN STRUCTURE: only a check the assert/branch GUARANTEES may be
    # credited. `assert(A && B)` guarantees both; `assert(A || B)` guarantees
    # NEITHER individually (A is bypassable whenever B holds), so everything below
    # an `||` is marked un-guaranteed.
    #
    # LENGTH vs VALUE: `assert(len(arg) == 8)` before `btoi(arg)` shares the
    # register and the input slot with the sink but bounds only the LENGTH -- the
    # attacker still picks any 8-byte value. `value_ok` goes false under
    # `_VALUE_OPAQUE_OPS` exactly as `guaranteed` goes false under `||`; a
    # value-preserving conjunct (`len==8 && btoi(arg) <= max`) still credits.
    #
    # COMPARISON SENSE: a sender check authorises only when it RESTRICTS the
    # sender. `Sender == creator` does; `Sender != creator` admits everyone BUT
    # the creator, and a payout on the FALSE edge of `Sender == creator` runs
    # precisely when the caller is not the creator. `sense` is what the enclosing
    # condition must evaluate to for the guard to hold -- True normally, False on
    # a branch whose FALSE edge reaches the sink; `!` flips it, and De Morgan
    # swaps which connective destroys the guarantee.
    ci = cs = False
    # Key the visited-set on the CONTEXT, not the register: one register can be
    # reached under different (guaranteed, value_ok, sense, sender_ok) flags
    # (`(A||B) && A`), and since the flags only weaken down a path, a stronger
    # path must still credit after a weaker one was walked.
    seen: set = set()

    def _comparison_pins_sender(src) -> bool:
        """Exactly one operand is Sender and the other is a trusted identity.

        An attacker-supplied counterpart authorises nothing
        (``Sender == ApplicationArgs[2]`` is satisfied by any caller who passes
        their own address), nor does ``CreatorAddress == arg`` check Sender at
        all. Constants must be 32-byte non-zero address values.

        HAZARD: walk the operand's whole def-tree, not just its defining op. An
        ARC-4 address argument reaches the comparison through at least one
        `extract`, so a one-hop check saw only that `extract` and credited a
        sender guard for the COMPILED spelling of the very idiom it exists to
        refuse — while correctly refusing the hand-written one. The benchmark
        pinned only the direct form, so nothing caught it."""
        def has_sender(a) -> bool:
            return any(
                _is_sender_op(_intr(oo) if oo is not None else None)
                for _r, oo in _walk(a, def_of, inv_ret=inv_ret)
            )

        sender_arms = [has_sender(a) for a in src.args]
        if sum(sender_arms) != 1:
            return False
        other = src.args[0] if sender_arms[1] else src.args[1]
        if isinstance(other, pre_ir.UInt64Constant):
            return False
        if isinstance(other, pre_ir.BytesConstant):
            h = other.value[2:] if other.value.startswith("0x") else other.value
            return len(h) == 64 and not set(h) <= {"0"}
        for _r, oo in _walk(other, def_of, inv_ret=inv_ret):
            s = _intr(oo) if oo is not None else None
            if s is None:
                continue
            imm = " ".join(str(i) for i in (s.immediates or []))
            if (source_label(s) is not None or s.op.startswith("gtxn")
                    or (s.op == "global" and imm in {
                        "CallerApplicationID", "CallerApplicationAddress",
                    })):
                return False
        return True

    def visit(value, guaranteed, value_ok, sense, sender_ok, input_ok=True, depth=0):
        nonlocal ci, cs
        if not isinstance(value, pre_ir.Register) or depth > 8:
            return
        key = (id(value), guaranteed, value_ok, sense, sender_ok, input_ok)
        if key in seen:
            return
        seen.add(key)
        o = def_of.get(id(value))
        src = _intr(o) if o is not None else None
        if (src is not None and src.op in _CMP_OPS and len(src.args) == 2
                and src.args[0] is src.args[1]):
            return                              # x OP x is a constant predicate
        if (src is not None and src.op == "%" and len(src.args) == 2
                and isinstance(src.args[0], pre_ir.UInt64Constant)
                and src.args[0].value == 1):
            return                              # x % 1 is always zero
        if guaranteed and value_ok and input_ok:
            if id(value) in sink_regs:
                ci = True
            if src is not None:
                if _is_sender_op(src) and sender_ok:
                    cs = True
                if _input_key(src) in sink_keys:
                    ci = True
        # De Morgan: `||` breaks the guarantee under a required-True condition,
        # `&&` under a required-False one.
        breaks = "||" if sense else "&&"
        child_guar = guaranteed and not (src is not None and src.op == breaks)
        child_val = value_ok and not (src is not None and src.op in _VALUE_OPAQUE_OPS)
        child_sense = (not sense) if (src is not None and src.op == "!") else sense
        # An equality that must hold PINS a sender read below it; one that must
        # NOT hold (or a `!=` that must) only excludes one address.
        child_sender = sender_ok
        if src is not None and src.op in _EQ_OPS:
            child_sender = child_sense and _comparison_pins_sender(src)
        elif src is not None and src.op in _NEQ_OPS:
            child_sender = (not child_sense) and _comparison_pins_sender(src)
        # A relation that only EXCLUDES one value restricts nothing about which
        # value the sink gets. `assert(recipient != ZeroAddress)` says the payee is
        # not the zero address; every other address still passes, so it is not a
        # check on WHO gets paid. Ordering relations (`<=`, `<`, …) and a pinning
        # `==` do constrain, and keep the credit. This mirrors what `sender_ok`
        # already does for the sender — the asymmetry was the bug: one side of
        # `_EQ_OPS`/`_NEQ_OPS` x sense was implemented, the other was not.
        child_input = input_ok
        if src is not None and (
                (src.op in _NEQ_OPS and child_sense)
                or (src.op in _EQ_OPS and not child_sense)):
            child_input = False
        if src is not None:
            for a in src.args:
                visit(a, child_guar, child_val, child_sense, child_sender,
                      child_input, depth + 1)
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            visit(o.source, child_guar, child_val, child_sense, child_sender,
                  child_input, depth + 1)
        elif isinstance(o, pre_ir.Phi):
            for pa in o.args:
                visit(pa.value, child_guar, child_val, child_sense, child_sender,
                      child_input, depth + 1)
        if inv_ret:                       # descend into an asserted validation sub
            for rv in inv_ret.get(id(value), ()):
                visit(rv, child_guar, child_val, child_sense, child_sender,
                      child_input, depth + 1)

    visit(cond, True, True, polarity != "false", False)
    return Guard(kind, polarity, ci, cs)


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
                       inv_ret=None) -> list:
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
                guards.append(_classify("assert", None, o.condition, def_of,
                                        sink_regs, sink_keys, inv_ret))
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
                    guards.append(_classify("branch", "true" if nz else "false",
                                            t.condition, def_of, sink_regs, sink_keys,
                                            inv_ret))
    return guards


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

    @property
    def guarded(self) -> bool:
        return any(g.checks_input or g.checks_sender for g in self.guards)

    def pretty(self) -> str:
        gd = (", guarded by " + "; ".join(g.describe() for g in self.guards
                                          if g.checks_input or g.checks_sender)) \
            if self.guarded else \
            ("  [param-derived: guard may be in a caller]" if self.param_derived
             else "  ** UNGUARDED **")
        src = "+".join(sorted(self.sources))
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


def _entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret=None):
    """Interprocedural guard summary ``{sub.id: {param_idx: (checks_input,
    checks_sender)}}``, plus the set of subs that are called somewhere.

    HAZARD: param ``i`` of sub ``S`` is entry-guarded only if EVERY call site
    passing a TAINTED value for arg ``i`` dominates that call with a guard on
    that value or the sender -- AND-across-sites, because the guard must hold on
    every path in. Transitive through the caller's own params; monotone fixpoint,
    so guards only grow. An untainted-passing site cannot expose the sink, so it
    does not constrain the summary."""
    subs = {s.id: s for s in lifter.subs}
    # Per-call-site arg facts, computed once (only the transitive part changes
    # across iterations): (caller_id, tainted, intra_input, intra_sender,
    # [caller param indices the arg flows from]).
    recs: dict = {sid: [] for sid in subs}
    for s in lifter.subs:
        dom, by_id = dom_by_sub[s.id], {b.id: b for b in s.body}
        cpidx = {id(p.register): i for i, p in enumerate(s.parameters)}
        for b in s.body:
            for idx, o in enumerate(b.ops):
                inv = _invoke(o)
                if inv is None or inv.target not in subs:
                    continue
                facts = []
                for arg in inv.args:
                    walked = list(_walk(arg, def_of))
                    aregs = {id(r) for r, _ in walked}
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
                                                akeys, inv_ret)
                    facts.append((s.id, any(r in taint for r in aregs),
                                  any(g.checks_input for g in guards),
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
                    cid, tainted, ci0, cs0, ks = facts[i]
                    if not tainted:
                        continue                  # safe site: doesn't constrain
                    seen = True
                    # HAZARD: ``ks`` lists EVERY caller-param in this argument's
                    # def tree, so a composite like ``p0 + p1`` lists both.
                    # Credit the transitive guard only when ALL are guarded at
                    # the caller's entry — with ``any``, validating just ``p0``
                    # and passing ``p0 + p1`` marks the argument guarded and
                    # SUPPRESSES the flow through the unchecked ``p1``. Empty
                    # ``ks`` must carry no credit (``all(())`` is vacuously
                    # True), hence the explicit ``bool(ks)``.
                    all_ci &= ci0 or bool(ks) and all(eg[cid][k][0] for k in ks)
                    all_cs &= cs0 or bool(ks) and all(eg[cid][k][1] for k in ks)
                new = (seen and all_ci, seen and all_cs)
                if new != eg[tid][i]:
                    eg[tid][i] = new
                    changed = True
    return eg, called


def _callee_param_guards(lifter, def_of, dom_by_sub, inv_ret=None) -> dict:
    """``{sub.id: {param_idx: (checks_input, checks_sender)}}`` — guards a sub
    applies to a param INTERNALLY that hold on RETURN (they dominate every
    ``SubroutineReturn``, so a post-call use of the caller's argument is
    constrained).

    The callee-side complement of :func:`_entry_guards`, covering a helper that
    ``assert``s its own parameter and returns nothing. Runs through
    :func:`_classify` like every other guard, so it records WHAT the check tests
    rather than a bare "is asserted"."""
    out: dict = {}
    for s in lifter.subs:
        dom, by_id = dom_by_sub[s.id], {b.id: b for b in s.body}
        rets = [b for b in s.body
                if isinstance(b.terminator, pre_ir.SubroutineReturn)]
        pg: dict = {}
        for i, p in enumerate(s.parameters):
            preg = {id(p.register)}
            ci = cs = bool(rets)          # AND across returns; no returns -> unknown
            for rb in rets:
                gs = _dominating_guards(by_id, dom, rb.id, len(rb.ops), def_of,
                                        preg, set(), inv_ret)
                ci = ci and any(g.checks_input for g in gs)
                cs = cs and any(g.checks_sender for g in gs)
            pg[i] = (ci, cs)
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
        ok = bool(rets)
        for rb in rets:
            # Empty match sets: `_classify` sets `checks_sender` from a sender
            # read under a pinning equality, with no reference to sink_regs.
            gs = _dominating_guards(by_id, dom, rb.id, len(rb.ops), def_of,
                                    set(), set(), inv_ret)
            ok = ok and any(g.checks_sender for g in gs)
        out[s.id] = ok
    return out


def _tainted_sink_flows(lifter, sink_of, taint=None, trusted_args=frozenset(),
                        sender_only=False) -> list:
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
    guards a different, unchecked one."""
    if taint is None:
        taint = user_input_taint(lifter, trusted_args)
    else:
        # A caller-supplied abstraction replaces the input source lattice, not
        # TOP. Preserve ``Undefined -> op -> register`` through custom views.
        taint = _merge_unresolved(lifter, taint)
    def_of = _def_map(lifter)
    dom_by_sub = {s.id: _dominators(s) for s in lifter.subs}
    pdom_by_sub = {s.id: _post_dominators(s) for s in lifter.subs}
    # Value edges the def-walk follows: a call result into the callee's returns,
    # plus a scratch round-trip back to what was stored (same map shape).
    inv_ret = _invoke_returns(lifter)
    inv_ret.update(_scratch_value_edges(lifter, dom_by_sub))
    entry_guards, called = _entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret)
    callee_pg = _callee_param_guards(lifter, def_of, dom_by_sub, inv_ret)
    callee_sender = _callee_sender_guards(lifter, def_of, dom_by_sub, inv_ret)
    findings: list = []
    for sub in lifter.subs:
        dom = dom_by_sub[sub.id]
        pdom = pdom_by_sub[sub.id]
        by_id = {b.id: b for b in sub.body}
        pidx = {id(p.register): i for i, p in enumerate(sub.parameters)}
        for b in sub.body:
            for idx, o in enumerate(b.ops):
                s = _intr(o)
                if s is None:
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
                        walked = list(_walk(valreg, def_of, inv_ret=inv_ret))
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
                                                sink_keys, inv_ret)
                    # A failed assert reverts the inner txn too, so one the sink
                    # cannot avoid reaching gates it as well.
                    guards += _post_dominating_guards(by_id, pdom, b.id, idx, def_of,
                                                      guard_regs, sink_keys, inv_ret)
                    # Interprocedural: a value flowing from a caller-checked param.
                    feeding = {pidx[r] for r in sink_regs if r in pidx}
                    egp = entry_guards.get(sub.id, {})
                    if any(egp.get(i, (False, False))[0] for i in feeding):
                        guards.append(Guard("caller", None, True, False))
                    if any(egp.get(i, (False, False))[1] for i in feeding):
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
                                aw = list(_walk(arg, def_of))
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
                                    if cs:
                                        guards.append(Guard("callee", None, False, True))
                    if sender_only:
                        # Byte-taint owns input validation (byte-precise); drop
                        # input-slot guards so only sender/creator checks clear.
                        guards = [g for g in guards if g.checks_sender]
                    guarded = any(g.checks_input or g.checks_sender for g in guards)
                    param_derived = bool(feeding) and not guarded and sub.id not in called
                    findings.append(FundFlowFinding(
                        label, severity, frozenset(sources),
                        sub.id, s.line, guards, param_derived, valreg))
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


# Persistent-state-write ops -> the index of their KEY operand in the lifted
# Intrinsic's args. HAZARD: args are TOP-FIRST (arg[0] is the LAST value pushed),
# so these indices read backwards from TEAL source order. Only the KEY is flagged
# — it is the destination slot a tainted value lets the attacker choose, whereas
# storing user data in the VALUE is normal.
_STATE_WRITE_KEY_IDX = {
    "app_global_put": 1,    # args: value, KEY
    "app_local_put": 1,     # args: value, KEY, account
    "app_global_del": 0,    # args: KEY (attacker-chosen global slot deleted)
    "app_local_del": 0,     # args: KEY, account
    "box_put": 1,           # args: value, KEY
    "box_create": 1,        # args: size, KEY
    "box_replace": 2,       # args: bytes, start, KEY
    "box_splice": 3,        # args: replacement, length, start, KEY
    "box_resize": 1,        # args: size, KEY
    "box_del": 0,           # args: KEY (attacker-chosen box deleted)
}
_STATE_WRITE_SEV = {
    "app_global_put": "CRITICAL",   # overwrite ANY global slot (owner/admin state)
    "app_local_put": "HIGH",
    "app_global_del": "CRITICAL",   # delete ANY global slot (owner/admin/pause key)
    "app_local_del": "HIGH",
    "box_put": "HIGH", "box_replace": "HIGH", "box_splice": "HIGH",
    "box_create": "MEDIUM", "box_resize": "MEDIUM",
    "box_del": "MEDIUM",            # delete an arbitrary (e.g. another user's) box
}


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
    return _tainted_sink_flows(lifter, _state_write_sink_of, taint, trusted_args)


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
