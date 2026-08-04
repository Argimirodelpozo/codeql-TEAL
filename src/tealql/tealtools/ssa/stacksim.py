"""A CLEAN per-routine stack simulation over the PySSA block model.

The replacement candidate for the fat-band half of :mod:`.ssa`. It is the same
algorithm the lift's ``_resim`` runs — real ``callsub`` arities, frame slots read
and written in place, phis built at joins — but in PyVar space, so its output can
fill ``Assignment.inputs`` directly instead of being translated into the lift's
register space.

WHY A SECOND MODEL IS THE PROBLEM IT SOLVES: there are three stack simulations in
this pipeline today (Braun's ``_read_exit``, phase 6c's ``local_stack``, and
``_resim``), and every PAIR of them has produced a silent wrong-value bug —
Braun vs 6c in the callsub work, SSA vs resim in ``(itob 0x151f7c75)``. Each was
invisible until a bespoke metric went looking. One simulator cannot disagree with
itself.

RUNS ALONGSIDE, DECIDES NOTHING (for now). :func:`simulate` is pure: it returns
operands keyed by op identity and never mutates the program, so it can be
differentiated against the incumbent on the corpus before anything switches over.
"""
from __future__ import annotations

from typing import Optional

from ..avm import op_arity


def _imm_int(op) -> Optional[int]:
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


def _narrow(o) -> tuple:
    """The op's CANONICAL arity, never its recorded one.

    ``PyOp.n_in``/``n_out`` are rewritten in place by the fat-band expansion, so
    reading them would make this simulation depend on whether the model it
    replaces has already run."""
    return op_arity(o.op, o.immediates)


def _callee_of(b, bb_to_sub):
    """The routine a ``callsub`` block enters — the successor that owns itself."""
    return next((s for s in b.succs if bb_to_sub.get(s) is s), None)


def infer_arities(blocks, bb_to_sub, proto_io, return_point,
                  divergent=None) -> dict:
    """``sub entry -> (nargs, nret)``, read off ``proto`` or inferred.

    A thin binding of :func:`..subroutines.infer_legacy_arities` to the PyBlock
    model — the fixpoint itself lives there, shared with the lift, because the
    two copies of it drifted and the SSA's under-counted at shared tails.

    THE DIP FOLLOWS CONTROL FLOW, NOT OWNERSHIP, which is what `owned_only=False`
    buys: a plain branch out of the owned body is still this routine executing.
    A shared tail (one block several routines `b` into, ending in `retsub`)
    belongs to exactly one of them under `pyblock_partition`, so measuring the
    dip over the owned body alone stops at the branch. Real case,
    app_1050006430 `label23`: body of one block popping 1, branching into
    `label75` which pops 3 more; its call sites push FOUR, so the simulation
    consumed one and stranded three, and every operand after the call in that
    caller was off by three. Nothing caught it — a too-DEEP stack yields wrong
    operands, not missing ones.
    """
    from ..subroutines import infer_legacy_arities

    subs = [b for b in blocks if bb_to_sub.get(b) is b]
    bodies: dict = {}
    for b in blocks:
        bodies.setdefault(bb_to_sub.get(b), []).append(b)
    return infer_legacy_arities(
        subs,
        entry_of=lambda s: s,
        proto_of=lambda s: proto_io.get(s),
        body_of=lambda s: set(bodies.get(s, ())),
        ops_of=lambda b: b.ops,
        succs_of=lambda b, body: _isucc(b, body, return_point, owned_only=False),
        callee_of=lambda b: _callee_of(b, bb_to_sub),
        op_arity=_narrow,
        divergent=divergent,
    )


class _Result:
    """What one simulation produced.

    ``args``  — ``id(PyOp) -> [operand]``, TOP-FIRST, matching ``PyOp.inputs``.
    ``phis``  — ``PyBlock -> [(slot, PyPhi)]`` merges created at joins.
    ``exit``  — ``PyBlock -> [operand]`` bottom-first, for the differential only.
    ``unresolved`` — ops the sim could not give a full operand list.
    ``divergent`` — legacy sub entries whose ``retsub`` sites leave DIFFERENT
    depths (no single ``(nargs, nret)`` describes them); their call sites take
    the depth-shift merge in :func:`_exec` instead of the uniform window.
    """

    __slots__ = ("args", "phis", "exit", "unresolved", "divergent")

    def __init__(self):
        self.args: dict = {}
        self.phis: dict = {}
        self.exit: dict = {}
        self.unresolved: set = set()
        self.divergent: set = set()


class _Param:
    """A routine's incoming stack slot — the value a caller left there.

    Deliberately NOT resolved to the callers' values here. Cross-call value flow
    is the call-site bridges' job (``passes.frame_flow.frame_param_sources``
    reconstructs it from each ``callsub`` block), and threading it inline is what
    forced the old model to carry a whole-program stack and cap it at
    ``STACK_MAX``."""

    __slots__ = ("sub_key", "index")

    def __init__(self, sub_key, index):
        self.sub_key = sub_key
        self.index = index

    def __repr__(self) -> str:
        return f"param{self.index}@{self.sub_key[1]}"


def simulate(blocks, bb_to_sub, proto_io, return_point, phi_factory,
             *, bind_params: bool = True, unsafe_callees=frozenset()) -> "_Result":
    """Simulate every routine and return a :class:`_Result`.

    ``phi_factory(block, slot) -> phi`` mints the merge value, so the caller
    decides what a phi IS (a ``PyPhi`` in the builder, a stand-in in a test).

    ``unsafe_callees`` — routine entries that reach BELOW their own band (see
    ``ssa._classify_call_effects``). A per-routine simulation cannot see this by
    construction: the callee's dip happens on ITS local stack, so the caller's
    residual sits here untouched and every value below the call reads as its
    pre-call self. That is the silent-wrong-value shape, not a missing feature —
    so the caller's residual is withdrawn at such a call instead.

    ``bind_params`` resolves each routine's incoming slots to what its call
    sites pass. ON: the 2% it appeared to cost was a MEASUREMENT artifact —
    559 of the 591 extra "disagreements" over 40 probes were the incumbent
    holding a NARROW ``frame_dig`` output, which has no inputs and so resolves
    to nothing. Binding names a value the incumbent leaves dangling, and that
    dangling form is precisely the output-with-no-inputs shape that reads clean
    to every may-analysis."""
    res = _Result()
    # Real arities FIRST: a legacy callee's (nargs, nret) is not declared
    # anywhere, and treating it as (0, 0) leaves its arguments on the caller's
    # stack — which the caller's next op then consumes. The fixpoint also
    # names the DIVERGENT legacy subs (retsub sites at different depths):
    # their calls need the depth-shift merge, not the uniform window.
    arity = infer_arities(blocks, bb_to_sub, proto_io, return_point,
                          divergent=res.divergent)
    by_sub: dict = {}
    for b in blocks:
        by_sub.setdefault(bb_to_sub.get(b), []).append(b)

    # Callee entry -> the values its `retsub` blocks leave on top, so a call site
    # can push real results instead of threading the return edge.
    retsubs: dict = {}
    for b in blocks:
        if b.ops and b.ops[-1].op == "retsub":
            retsubs.setdefault(bb_to_sub.get(b), []).append(b)

    # CALLEES FIRST. A call site pushes the values its callee's `retsub` blocks
    # leave, so simulating a caller before its callee makes every call result
    # None — and the ops consuming them then read as unresolved rather than
    # wrong, which is exactly the kind of hole a differential skips over.
    deferred: list = []
    for sub in _callee_first(by_sub, bb_to_sub):
        _run_routine(sub, by_sub[sub], res, arity, bb_to_sub, return_point,
                     retsubs, phi_factory, unsafe_callees, deferred, proto_io)
    # Blocks NO root claims (``bb_to_sub`` misses them) never simulate, and
    # their ops kept EMPTY inputs with no refusal marker — silence, not
    # honesty. ``pyblock_partition`` now roots the program entry
    # unconditionally, so this group should stay empty on real programs; any
    # block that still lands here gets its consuming ops LISTED as unresolved,
    # so the gap can never again read as clean.
    for b in by_sub.get(None, ()):
        for o in b.ops:
            if _narrow(o)[0] or o.op in ("callsub", "frame_dig", "frame_bury"):
                res.unresolved.add(id(o))
    # RECURSION. A cycle has no callee-first order, so a call inside it reaches
    # `retsub` blocks that are not simulated yet. Braun's answer to the same
    # problem is to hand out the phi BEFORE recursing and complete it after; that
    # is what `deferred` is. Filling the arguments now — every routine has run —
    # closes the cycle: `count_len`'s result becomes φ(0, φ+1), which is exactly
    # the inductive shape a prover needs. Pushing None instead cost avm-prover
    # the proof that `r == len(arg0)`.
    for ph, slot, j, proto, rets in deferred:
        for rb in rets:
            if rb not in res.exit:
                continue
            v = _return_value(res.exit[rb], j, slot, proto)
            if v is not None and not any(a is v for a in ph.args):
                ph.args.append(v)
    if bind_params:
        _bind_params(blocks, res, arity, bb_to_sub, phi_factory)
    return res



def _return_value(st, j, slot, proto):
    """The value a callee's `retsub` block leaves as return ``j`` (0 = first).

    `proto A R` returns FRAME SLOTS 0..R-1 -- the first R locals, just above the
    A args -- NOT the top R of the stack. Reading the top finds it only when the
    callee happens to leave it there; one that parks it with `frame_bury 0` and
    keeps working locals above hands the caller its LEFTOVER, or nothing when the
    stack is shallower than R. Measured on app_2645463331 `label172`
    (`proto 2 1`): retsub exit is [param0, param1, <return>, leftover], so the
    top read took the leftover.

    A LEGACY sub is NOT "a sub without a frame" -- it can use `frame_dig` /
    `frame_bury` perfectly well, addressed off its INFERRED nargs. The reason it
    reads from the top instead is TRUNCATION: `proto`'s `retsub` truncates to
    the frame and moves slots 0..R-1 down, so the caller sees exactly those
    slots; a pre-`proto` `retsub` truncates NOTHING, so the caller receives the
    callee's exit stack verbatim and physically consumes whatever is on top --
    even if the callee also parked a value with `frame_bury 0`.
    """
    if proto is not None:
        pos = proto[0] + j
        return st[pos] if 0 <= pos < len(st) else None
    return st[-slot] if len(st) >= slot else None


def _callee_first(by_sub, bb_to_sub):
    """Routine entries ordered so a callee precedes its callers.

    Recursion has no such order, so a cycle is emitted in discovery order; the
    calls inside it get a phi completed after every routine has run (see
    ``deferred`` in :func:`simulate`). The historical note below described the
    state before that existed — a cycle's call results stayed unresolved, which
    was honest, and the only
    thing a single pass can say."""
    calls: dict = {}
    for sub, body in by_sub.items():
        if sub is None:
            continue
        seen: set = set()
        for b in body:
            if b.ops and b.ops[-1].op == "callsub":
                c = _callee_of(b, bb_to_sub)
                if c is not None and c is not sub:
                    seen.add(c)
        calls[sub] = seen

    order: list = []
    state: dict = {}                        # 0 = visiting, 1 = done

    def visit(s):
        st = state.get(s)
        if st is not None:
            return                          # done, or a cycle we must not re-enter
        state[s] = 0
        for c in calls.get(s, ()):
            if state.get(c) is None:
                visit(c)
        state[s] = 1
        order.append(s)

    for s in calls:
        visit(s)
    return order


def _bind_params(blocks, res, arity, bb_to_sub, phi_factory):
    """Replace every :class:`_Param` with what the CALL SITES actually pass.

    Simulating a routine leaves its incoming slots symbolic, because a callee is
    walked without knowing its callers. Binding them afterwards is what makes the
    result whole-program: the args a ``callsub`` popped are already recorded in
    ``res.args``, so param ``i`` (0 = deepest) is arg ``A-1-i`` at each site,
    merged with a phi when a routine has several callers.

    The phi is created BEFORE it is filled, so a recursive routine — whose own
    body contains a call that supplies one of its params — terminates instead of
    recursing forever."""
    sites: dict = {}                       # sub -> [callsub block]
    for b in blocks:
        if b.ops and b.ops[-1].op == "callsub":
            callee = _callee_of(b, bb_to_sub)
            if callee is not None:
                sites.setdefault(callee, []).append(b)

    bound: dict = {}                       # (sub.key, index) -> value
    minted: list = []
    for sub, callers in sites.items():
        a_in = arity.get(sub, (0, 0))[0]
        for i in range(a_in):
            vals = []
            for cb in callers:
                args = res.args.get(id(cb.ops[-1]))
                pos = a_in - 1 - i         # top-first within the call's args
                if args and pos < len(args) and args[pos] is not None:
                    vals.append(args[pos])
            key = (sub.key, i)
            if len({id(v) for v in vals}) == 1:
                # Every call site passes the SAME value — a phi over it would be
                # trivial the moment it was built. Counting `vals` instead of
                # deduping them minted one per multi-site callee.
                bound[key] = vals[0]
            elif vals:
                ph = phi_factory(sub, a_in - i)
                bound[key] = ph
                ph.args.extend(vals)
                minted.append(ph)

    def resolve(v, depth=0):
        while isinstance(v, _Param) and depth < 16:
            nxt = bound.get((v.sub_key, v.index))
            if nxt is None or nxt is v:
                return None                # no call site supplies it
            v, depth = nxt, depth + 1
        # The hop budget can exhaust with ``v`` STILL a _Param — a 17-deep
        # verbatim pass-through chain is enough (each wrapper's callsub hands
        # its own untouched param on). Returning it leaked a private simulator
        # marker into public ``Assignment.inputs``, where the first consumer to
        # touch ``.key()``/``.defined_by`` dies. Exhaustion is a refusal.
        return None if isinstance(v, _Param) else v

    for k, ins in res.args.items():
        for j, v in enumerate(ins):
            if isinstance(v, _Param):
                ins[j] = resolve(v)
    for b, st in res.exit.items():
        for j, v in enumerate(st):
            if isinstance(v, _Param):
                st[j] = resolve(v)
    for phis in res.phis.values():
        for _slot, ph in phis:
            ph.args = [resolve(a) if isinstance(a, _Param) else a for a in ph.args]
    # The phis minted RIGHT HERE need it too. A call site may pass one of its own
    # caller's params straight through, so a param phi's arguments can themselves
    # be `_Param`s — and these phis are not in `res.phis`, so the sweep above
    # never reached them. Left unresolved, a private marker escapes into a public
    # phi and the first consumer to call `.key()` on it dies.
    for ph in minted:
        ph.args = [resolve(a) if isinstance(a, _Param) else a for a in ph.args]


def _isucc(b, body, return_point, *, owned_only=True):
    """Successors INSIDE the routine: a call flows to its continuation, never
    into the callee, and a return leaves.

    ``owned_only=False`` drops the body filter for PLAIN branches, for the
    arity walk: a shared tail is owned by one routine but executed by several,
    and the dip has to be measured over what runs, not over what is owned. The
    simulation keeps the filter — ownership is exactly what decides whose stack
    a block runs on."""
    if b.ops and b.ops[-1].op in ("retsub", "return", "err"):
        return []
    if b.ops and b.ops[-1].op == "callsub":
        cont = return_point.get(b)
        return [cont] if cont is not None and (cont in body or not owned_only) else []
    return [s for s in b.succs if s in body or not owned_only]


def _run_routine(sub, body_list, res, arity, bb_to_sub, return_point,
                 retsubs, phi_factory, unsafe_callees=frozenset(),
                 deferred=None, proto_io=None):
    divergent = res.divergent
    body = set(body_list)
    nargs = arity.get(sub, (0, 0))[0]

    WHITE, GRAY = 0, 1
    color: dict = {}
    back: set = set()

    def dfs(start):
        stack = [(start, iter(_isucc(start, body, return_point)))]
        color[start] = GRAY
        while stack:
            b, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                color[b] = 2
                stack.pop()
                continue
            c = color.get(nxt, WHITE)
            if c == GRAY:
                back.add((b, nxt))
            elif c == WHITE:
                color[nxt] = GRAY
                stack.append((nxt, iter(_isucc(nxt, body, return_point))))

    dfs(sub)
    back_targets = {d for _, d in back}
    fpred: dict = {b: [] for b in body_list}
    bpred: dict = {b: [] for b in body_list}
    for b in body_list:
        for su in _isucc(b, body, return_point):
            (bpred if (b, su) in back else fpred).setdefault(su, []).append(b)

    order, seen = [], set()

    def visit(start):
        stack = [(start, iter(_isucc(start, body, return_point)))]
        seen.add(start)
        while stack:
            b, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                order.append(b)
                stack.pop()
                continue
            if (b, nxt) not in back and nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, iter(_isucc(nxt, body, return_point))))

    visit(sub)
    order.reverse()
    order += [b for b in body_list if b not in seen]

    # Local predecessor count, for deciding where a call-result merge may live.
    npred = {b: len(fpred.get(b, ())) + len(bpred.get(b, ())) for b in body_list}

    pending: list = []
    for b in order:
        preds = [p for p in fpred.get(b, ()) if p in res.exit]
        stack = _entry_stack(b, sub, nargs, preds, back_targets,
                             bpred.get(b, ()), pending, res, phi_factory)
        for o in b.ops:
            _exec(o, b, stack, nargs, res, bb_to_sub, retsubs, arity,
                  phi_factory, unsafe_callees, return_point, npred, deferred,
                  proto_io, divergent)
        res.exit[b] = stack
    for ph, slot, depth, bp in pending:
        # TOP-aligned, matching the loop-header merge above.
        if bp in res.exit and len(res.exit[bp]) >= depth:
            ph.args.append(_at(res.exit[bp], depth, slot))


def _at(stack, depth, i):
    """The value at merged position ``i`` (0 = bottom of the merged window).

    ALIGNED BY THE TOP. Predecessors of a join can arrive at DIFFERENT depths —
    legal TEAL, and common at a dispatch chain where one arm still holds a value
    the others consumed — and what corresponds across them is the TOP of the
    stack, never the bottom. Indexing bottom-first reads a deeper predecessor's
    residual instead of the value it actually leaves at that slot: at
    app_1100218544 L359 three preds arrive at depth 1 and one at depth 2, and
    bottom-first indexing gave the phi that pred's `n0` instead of the
    `ApplicationArgs 3` sitting on top of it."""
    return stack[len(stack) - depth + i]


def _entry_stack(b, entry, nargs, preds, back_targets, bpred_b, pending,
                 res, phi_factory):
    if b is entry:
        return [_Param(entry.key, i) for i in range(nargs)]
    if not preds:
        # No simulated predecessor: an unreachable block, or one whose preds the
        # walk could not order. Its entry stack is genuinely unknown, so REFUSE
        # — the previous fallback handed it the routine's parameters, which is a
        # guess that reads as a real value and would wire a data flow that does
        # not exist. Never observed on compiler output (0 such blocks over 12
        # probes); this is for the hand-written TEAL that can produce one.
        return []
    if b in back_targets:
        # TOP-aligned, like the plain join below — and NOT like the lift, which
        # merges loop headers bottom-first. That is not an oversight to copy:
        # the lift's phis are plain registers, while an SSA phi's IDENTITY is
        # `(bb_key, slot)` with slot counted TOP-first, and consumers read the
        # matching value as `pred.exit_stack[-slot]`. Bottom-first merging
        # breaks that correspondence wherever a predecessor is deeper than the
        # merge window — 11 violated phi-pred edges on app_3300088574, which
        # `test_frame_base_alignment` exists to catch.
        depth = min(len(res.exit[p]) for p in preds)
        stack, phis = [], []
        for slot in range(depth):
            ph = phi_factory(b, depth - slot)
            ph.args.extend(_at(res.exit[p], depth, slot) for p in preds)
            phis.append((slot, ph))
            stack.append(ph)
            for bp in bpred_b:
                pending.append((ph, slot, depth, bp))
        res.phis[b] = phis
        return stack
    if len(preds) == 1:
        return list(res.exit[preds[0]])
    depth = min(len(res.exit[p]) for p in preds)
    stack, phis = [], []
    for slot in range(depth):
        vals = [_at(res.exit[p], depth, slot) for p in preds]
        if all(v is vals[0] for v in vals):
            stack.append(vals[0])
            continue
        ph = phi_factory(b, depth - slot)
        ph.args.extend(vals)
        phis.append((slot, ph))
        stack.append(ph)
    if phis:
        res.phis[b] = phis
    return stack


def _exec(o, b, stack, nargs, res, bb_to_sub, retsubs, arity, phi_factory,
          unsafe_callees=frozenset(), return_point=None, npred=None,
          deferred=None, proto_io=None, divergent=frozenset()):
    """One op against the clean stack, recording its operands TOP-FIRST."""
    if o.op in ("frame_dig", "frame_bury"):
        n = _imm_int(o)
        pos = None if n is None else nargs + n
        if o.op == "frame_dig":
            if pos is not None and 0 <= pos < len(stack):
                # RECORD THE SOURCE as the read's input. Without it the op has no
                # inputs at all, which is the "output with no inputs" shape that
                # reads CLEAN to every may-analysis — and
                # `frame_flow.frame_unresolved_reads` is written to detect
                # exactly that, so a resolved read must not look like one.
                #
                # Push the op's OWN output, not the value it copied: `frame_dig`
                # pushes a copy on the AVM, and `_shuffle_mapping` says that
                # output IS input 0, so a resolver still reaches the original
                # while the read itself stays on the provenance chain. Pushing
                # the underlying value instead made the read invisible — its
                # declared output went dead and a chain crossing a call boundary
                # named `txna -> extract`, with no sign a frame read happened.
                res.args[id(o)] = [stack[pos]]
                stack.append(o.outputs[0] if o.outputs else stack[pos])
            else:
                res.unresolved.add(id(o))
                stack.append(None)
        else:
            if not stack:
                res.unresolved.add(id(o))
                return
            v = stack.pop()
            res.args[id(o)] = [v]
            if pos is not None and 0 <= pos < len(stack):
                stack[pos] = v
            elif pos == len(stack):
                stack.append(v)          # target IS the vacated cell
            else:
                res.unresolved.add(id(o))
        return
    if o.op == "callsub":
        callee = _callee_of(b, bb_to_sub)
        a_in, r_out = arity.get(callee, (0, 0)) if callee is not None else (0, 0)
        take = min(a_in, len(stack))
        res.args[id(o)] = [stack.pop() for _ in range(take)]
        if take < a_in:
            res.unresolved.add(id(o))
        if callee in unsafe_callees:
            # The callee reached below its own band with a PLAIN stack op, so
            # what sits underneath is whatever IT left — not what this routine
            # pushed. Blank the VALUES, keep the HEIGHT: the AVM re-checks the
            # frame bound at `retsub`, so a callee that dips must put the depth
            # back, and the frame base later `frame_dig`s anchor to is unmoved.
            #
            # The UNSAFE set, deliberately WIDER than the lift's clobber-only
            # policy. Narrowing it to match the lift broke six invariants
            # (`below_frame_bury_is_dead`, `height_ambiguous_join`, three
            # frame-flow tests, the two-simulator alignment): the lift can fall
            # back on `Undefined`, but SSA-level may-analyses read these slots
            # DIRECTLY, so "could not verify the band height" has to withdraw
            # here or it reads as a resolved pre-call value. The handful of
            # operands this costs are honest refusals, listed by
            # `unresolved_call_results`.
            stack[:] = [None] * len(stack)
        rets = retsubs.get(callee, ())
        # A merge over several `retsub` sites belongs to the CONTINUATION, not
        # here: the continuation is where those return paths actually join (its
        # CFG predecessors ARE the retsub blocks), so a phi placed there has one
        # argument per real incoming edge. Minted on this block instead, it
        # claimed to be an entry value of a block whose only predecessor is the
        # caller's own code, and the slot then resolved to the caller's value —
        # a phi standing for something none of its arguments can be.
        cont = return_point.get(b) if return_point is not None else None
        # `npred` is keyed on THIS routine's blocks, so membership doubles as the
        # in-body test — a continuation belonging to another routine has no
        # entry slot of ours to hold the merge.
        can_merge = cont is not None and npred is not None and \
            cont in npred and npred[cont] <= 1
        # A callee whose `retsub` blocks have not run yet is a RECURSION cycle
        # (callee-first ordering handles everything else). Its result is not
        # unknown — it is defined in terms of itself — so hand out a phi now and
        # fill it once every routine has run.
        pending_rets = [rb for rb in rets if rb not in res.exit]
        # See `_return_value`: proto'd returns live in FRAME SLOTS, legacy
        # ones on the physical stack top, because only proto's retsub truncates.
        a_proto = proto_io.get(callee) if proto_io is not None else None
        # A DIVERGENT legacy callee (retsub sites at different depths) is not
        # a function: `r_out` is the DEEPEST path's count, so the uniform
        # window below asserted the deep path's below-top cells for every path
        # — on the shallow path the "second return" is the CALLER's own
        # residual value, and the exit stacks are shifted against each other
        # all the way down. Both are exactly recoverable: a no-proto retsub
        # does not truncate, so the continuation stack on return path p is
        # (caller residual) + (p's exit stack) VERBATIM — every merged cell's
        # per-path truth is either p's exit cell or a caller residual cell at
        # a path-dependent offset. `shifted` takes that per-path merge; only a
        # cell BELOW a path's whole stack stays a refusal (consuming there
        # means that path is reading past everything this frame owns).
        shifted = a_proto is None and callee in divergent
        exits = [res.exit[rb] for rb in rets if rb in res.exit]
        if shifted and (pending_rets or not can_merge):
            # The shift needs every exit depth and a phi home; without either,
            # the residual's per-path offsets are unknowable — withdraw it
            # (heights kept) rather than let the pre-call values stand for
            # cells the shallow paths do not have.
            stack[:] = [None] * len(stack)
        pushes: list = []
        for j in range(r_out):
            slot = r_out - j                      # top-first within the returns
            if shifted and not pending_rets and can_merge:
                vals = [st[-slot] if len(st) >= slot
                        else (stack[len(st) - slot]
                              if slot - len(st) <= len(stack) else None)
                        for st in exits]
                if not vals or any(v is None for v in vals):
                    pushes.append(None)
                elif len({id(v) for v in vals}) == 1:
                    pushes.append(vals[0])
                else:
                    ph = phi_factory(cont, slot)
                    ph.args.extend(vals)
                    res.phis.setdefault(cont, []).append((slot, ph))
                    pushes.append(ph)
                continue
            vals = [v for st in exits
                    for v in (_return_value(st, j, slot, a_proto),)
                    if v is not None]
            if pending_rets and (shifted
                                 or not (can_merge and deferred is not None)):
                # A return path exists that we cannot merge in. Taking the
                # resolved subset would name the base case as THE result and
                # hide the recursive one — an under-approximation that reads as
                # a definite value. (A divergent callee joins this refusal:
                # its deferred fill would read `st[-slot]`, a wrong CELL on
                # the shorter paths, not merely a missing value.)
                pushes.append(None)
            elif pending_rets:
                ph = phi_factory(cont, slot)
                ph.args.extend(vals)
                res.phis.setdefault(cont, []).append((slot, ph))
                deferred.append((ph, slot, j, a_proto, tuple(pending_rets)))
                pushes.append(ph)
            elif len({id(v) for v in vals}) == 1:
                pushes.append(vals[0])    # every retsub leaves the same value
            elif vals and can_merge:
                ph = phi_factory(cont, slot)
                ph.args.extend(vals)
                res.phis.setdefault(cont, []).append((slot, ph))
                pushes.append(ph)
            else:
                # No continuation, or one that is ALSO a branch target — where a
                # slot-`slot` phi would collide with the join's own. Measured at
                # 1 call site in 1439 over 60 probes, so refusing costs almost
                # nothing and inventing a home for the phi would cost identity.
                pushes.append(None)
        if shifted and not pending_rets and can_merge and stack:
            # The residual TRAIL. Below the pushed window the paths stay
            # shifted by their depth difference forever, so model position
            # `r_out + d` holds a different caller cell per path — a phi per
            # cell down the residual, args all REAL values. A position past a
            # path's ENTIRE stack has no cell on that path (this frame owns
            # nothing deeper); one unknowable arm withdraws the cell, because
            # a phi that silently omits a path reads as clean to every
            # may-analysis.
            base = list(stack)
            for d in range(1, len(base) + 1):
                k = r_out + d
                args = [base[len(st) - k] if 0 < k - len(st) <= len(base)
                        else None
                        for st in exits]
                if not args or any(a is None for a in args):
                    v = None
                elif len({id(a) for a in args}) == 1:
                    v = args[0]
                else:
                    ph = phi_factory(cont, k)
                    ph.args.extend(args)
                    res.phis.setdefault(cont, []).append((k, ph))
                    v = ph
                stack[len(base) - d] = v
        stack.extend(pushes)
        return
    if o.op in ("proto", "intcblock", "bytecblock"):
        return
    n_in, _n_out = _narrow(o)
    ins = []
    for _ in range(n_in):
        ins.append(stack.pop() if stack else None)
    if any(i is None for i in ins):
        res.unresolved.add(id(o))
    res.args[id(o)] = ins
    for v in reversed(o.outputs):
        stack.append(v)
