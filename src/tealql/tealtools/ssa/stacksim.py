"""The canonical per-routine stack simulation over the PySSA block model.

It models real ``callsub`` arities, frame slots read and written in place, and
phis at joins.  The result is expressed in PyVar space so it can fill
``Assignment.inputs`` directly and serve as the shared semantic source for
downstream representations.

WHY A SECOND MODEL WAS THE PROBLEM IT SOLVED: the pipeline once had three stack
simulations (Braun's ``_read_exit``, phase 6c's ``local_stack``, and the lift's
``_resim``), and every pair produced a silent wrong-value bug. Traversal and
joins now live in :func:`walk_routine`; representation adapters only execute
their own opcode values. One scheduler cannot disagree with itself.

:func:`simulate` is pure: it returns operands keyed by op identity and never
mutates the program.  Keeping mutation at the caller boundary makes the engine
usable by both the SSA builder and lift adapters.
"""
from __future__ import annotations

from typing import Optional

from .callee_effects import _Below, _CalleeParam


def _imm_int(op) -> Optional[int]:
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


def _narrow(o) -> tuple:
    """The op's arity as recorded at instantiation.

    ``PyOp.n_in``/``n_out`` are set once from ``op_arity`` and never rewritten
    (the fat-band expansion that used to mutate them is deleted); re-parsing
    the immediates here cost ~5 string parses per op per build for nothing.
    ``_classify_call_effects`` already trusts the recorded fields."""
    return o.n_in, o.n_out


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
    from ..cfg.subroutines import infer_legacy_arities

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


class HeightResult:
    """Static entry-height lattice used by frame and call-effect analysis.

    ``entry`` contains only blocks with one exact bottom-anchored depth.
    ``conflicted`` contains height-conflicting blocks and their local suffix;
    ``poisoned`` additionally includes owned blocks whose depth is unavailable
    for another reason (for example an unverified call continuation). Keeping
    both sets prevents diagnostics from confusing ambiguity with absence while
    retaining the conservative gate frame consumers require.
    """

    __slots__ = ("entry", "poisoned", "conflicted")

    def __init__(self, entry, poisoned, conflicted):
        self.entry = entry
        self.poisoned = poisoned
        self.conflicted = conflicted


def entry_heights(blocks, bb_to_sub, proto_io, call_pairs,
                  arity=None) -> HeightResult:
    """Compute exact bottom-anchored entry depths for every routine block.

    ``call_pairs`` maps a verified callsub block to ``(continuation, A, R)``.
    Plain CFG edges never cross a frame; verified calls cross as ``-A + R``.
    A conflicting proposal poisons the whole locally reachable suffix instead
    of choosing one path's depth. This is the height half of the canonical
    stack model and replaces the SSA builder's separate phase-6c-era walk.

    A routine's entry depth is its ARGUMENT COUNT — ``proto``'s, or for a
    legacy sub the one ``arity`` (the shared :func:`infer_arities` map)
    inferred from its dip, which is exactly how many cells
    :func:`_run_routine` seeds its stack with. Rooting a legacy sub at 0
    while the simulation ran it at ``nargs`` made every height it reported
    off by ``nargs``.
    """
    def net(op):
        if op.op == "frame_dig":
            return 1
        if op.op == "frame_bury":
            return -1
        n_in, n_out = _narrow(op)
        return n_out - n_in

    arity = arity or {}
    roots = {
        block: (proto_io.get(block) or arity.get(block, (0, 0)))[0]
        for block in blocks if bb_to_sub.get(block) is block
    }
    entry = {block.key: depth for block, depth in roots.items()}
    work = list(roots)
    conflicted: list = []

    def local_successors(block):
        term = block.ops[-1].op if block.ops else None
        if term in ("callsub", "retsub"):
            return []
        owner = bb_to_sub.get(block)
        return [succ for succ in block.succs if bb_to_sub.get(succ) is owner]

    index = 0
    while index < len(work):
        block = work[index]
        index += 1
        depth = entry[block.key]
        for op in block.ops:
            depth += net(op)
        if depth < 0:
            depth = 0

        targets = []
        pair = call_pairs.get(block)
        if pair is not None:
            continuation, nargs, nret = pair
            crossed = depth - nargs + nret
            if crossed >= 0:
                targets.append((continuation, crossed))
        targets.extend((succ, depth) for succ in local_successors(block))
        for target, proposed in targets:
            old = entry.get(target.key)
            if old is None:
                entry[target.key] = proposed
                work.append(target)
            elif old != proposed:
                conflicted.append(target)

    conflicted_suffix: set = set()
    work = list(conflicted)
    while work:
        block = work.pop()
        if block.key in conflicted_suffix:
            continue
        conflicted_suffix.add(block.key)
        pair = call_pairs.get(block)
        if pair is not None and pair[0].key not in conflicted_suffix:
            work.append(pair[0])
        work.extend(succ for succ in local_successors(block)
                    if succ.key not in conflicted_suffix)
    for key in conflicted_suffix:
        entry.pop(key, None)
    poisoned = {block.key for block in blocks
                if bb_to_sub.get(block) is not None and block.key not in entry}
    return HeightResult(entry, poisoned, conflicted_suffix)


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

    __slots__ = ("args", "phis", "exit", "unresolved", "divergent",
                 "frame_deferred", "frame_skewed")

    def __init__(self):
        self.args: dict = {}
        self.phis: dict = {}
        self.exit: dict = {}
        self.unresolved: set = set()
        self.divergent: set = set()
        # (frame-slot phi, frame_bury PyOp) pairs whose arm the walk had not
        # recorded yet (a loop-carried write later in walk order); filled
        # once every routine has run, like `deferred` for recursion.
        self.frame_deferred: list = []
        # Routine entries where some op dipped BELOW the local model's bottom
        # (the pad kept executing but the list bottom no longer equals the
        # frame base). Every bottom-anchored coordinate there — `frame_dig`
        # positions, a proto'd retsub's return slots — is off by the
        # underflow, so those reads REFUSE instead of resolving one-per-cell
        # wrong. Legacy retsub reads are top-relative and stay unaffected.
        self.frame_skewed: set = set()


class _Param:
    """A routine's incoming stack slot — the value a caller left there.

    Deliberately NOT resolved to the callers' values here. Cross-call value flow
    is the call-site bridges' job (``ssa.relations.frame_param_sources``
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
             *, bind_params: bool = True, unsafe_callees=frozenset(),
             frame_analysis=None, poisoned=frozenset(),
             effect_summaries=None, arity=None,
             divergent_subs=None) -> "_Result":
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
    if frame_analysis is not None:
        frame_instructions = frame_analysis.instructions
        poisoned = frame_analysis.poisoned
    else:
        frame_instructions = {}
    # Real arities FIRST: a legacy callee's (nargs, nret) is not declared
    # anywhere, and treating it as (0, 0) leaves its arguments on the caller's
    # stack — which the caller's next op then consumes. The fixpoint also
    # names the DIVERGENT legacy subs (retsub sites at different depths):
    # their calls need the depth-shift merge, not the uniform window.
    # A caller that already ran the fixpoint (PySSA construction runs it for
    # call pairing) hands both results in rather than paying it again.
    if arity is None:
        arity = infer_arities(blocks, bb_to_sub, proto_io, return_point,
                              divergent=res.divergent)
    else:
        res.divergent.update(divergent_subs or ())
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
                     retsubs, phi_factory, unsafe_callees, deferred, proto_io,
                     frame_instructions, poisoned, effect_summaries)
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
            if proto is not None and rb.key in poisoned:
                # Same gate as the call site: a poisoned retsub's frame-slot
                # read goes through the frame-slot analysis; an unanswerable arm is
                # MARKED rather than silently omitted.
                ret = frame_instructions.get(id(rb.ops[-1]))
                instr = _return_slot(ret, j)
                v = _resolve_frame(instr, res)
                if v is None:
                    ph.partial = True
            else:
                skewed = (proto is not None
                          and bb_to_sub.get(rb) in res.frame_skewed)
                v = (None if skewed
                     else _return_value(res.exit[rb], j, slot, proto))
                if v is None:
                    # An unanswerable non-poisoned arm was silently OMITTED
                    # here — the resolved subset then read as the whole
                    # answer. Mark it, same as the poisoned gate above.
                    ph.partial = True
            if v is not None and not any(a is v for a in ph.args):
                ph.args.append(v)
    # Loop-carried frame-slot arms: the write's operand exists only after its block
    # ran, which for a write-after-read loop is after the reading dig. Every
    # routine has run now, so fill; an operand STILL unknown marks the phi
    # partial rather than silently narrowing it to the entry arm.
    for ph, wop in res.frame_deferred:
        wargs = res.args.get(id(wop))
        if wargs and wargs[0] is not None:
            if not any(a is wargs[0] for a in ph.args):
                ph.args.append(wargs[0])
        else:
            ph.partial = True
    if bind_params:
        _bind_params(blocks, res, arity, bb_to_sub, phi_factory)
    return res



def _frame_cells(instruction, res, *, allow_pending=False):
    """Resolve one :mod:`.frame_slots` slot merge against the walked
    state: ``(cells, pending_writes)`` — the resolved per-arm cells (one per
    region-entry predecessor where the entry value survives, plus each
    surviving write's operand) and the writes whose operand is NOT recorded
    yet (a loop-carried ``frame_bury`` whose block the walk has not reached;
    the arm is fillable after the routine finishes). Returns None where an
    arm is unknowable outright — a partial arm set would name the resolved
    subset as THE value — or where pending arms exist and the caller cannot
    defer (``allow_pending=False``)."""
    if instruction is None or not hasattr(instruction, "position"):
        return None
    entry_preds = instruction.entry_predecessors
    position = instruction.position
    writes = instruction.writes
    cells = []
    for pb in entry_preds:
        st = res.exit.get(pb)
        if st is None or position >= len(st) or st[position] is None:
            return None
        cells.append(st[position])
    pending = []
    for wop in writes:
        wargs = res.args.get(id(wop))
        if wargs and wargs[0] is not None:
            cells.append(wargs[0])
        elif allow_pending:
            pending.append(wop)
        else:
            return None
    if not cells and not pending:
        return None
    return cells, pending


def _frame_cell_root(value, seen=None, memo=None):
    """Collapse a loop phi that only carries one value plus itself.

    The ordinary stack join must keep ``phi(seed, self)`` structurally, but for
    a bottom-position equality proof it is exactly ``seed``. Without this
    normalization a stable frame local crossing an unrelated loop looks like
    two different boundary values and the multi-entry frame proof refuses it.
    """
    # ``phi(previous, previous)`` is a DAG, not a tree.  A copied path-local
    # seen set expands its shared predecessor once per path (exponential for a
    # chain of diamonds).  Resolve with an explicit post-order stack and one
    # identity memo.  ``active`` is separate from ``resolved``: conflating the
    # two makes the second arm of a diamond look cyclic and loses the exact
    # common root this helper exists to prove.
    active = set() if seen is None else set(seen)
    resolved = {} if memo is None else memo

    def args_of(node):
        try:
            return [arg for arg in node.args if arg is not node]
        except AttributeError:
            return None

    key = id(value)
    if key in resolved:
        return resolved[key]
    if key in active:
        return value
    first_args = args_of(value)
    if not first_args:
        resolved[key] = value
        return value

    # frame = [node, non-self args, next child index, resolved child roots]
    stack = [[value, first_args, 0, []]]
    active.add(key)
    while stack:
        node, args, index, roots = stack[-1]
        if index == len(args):
            root = (roots[0] if roots
                    and all(item is roots[0] for item in roots[1:])
                    else node)
            resolved[id(node)] = root
            active.discard(id(node))
            stack.pop()
            if not stack:
                return root
            stack[-1][3].append(root)
            stack[-1][2] += 1
            continue

        child = args[index]
        child_key = id(child)
        if child_key in resolved:
            roots.append(resolved[child_key])
            stack[-1][2] += 1
            continue
        if child_key in active:
            # Match the old path-local cycle semantics conservatively: the
            # repeated node is its own root on this arm.
            roots.append(child)
            stack[-1][2] += 1
            continue
        child_args = args_of(child)
        if not child_args:
            resolved[child_key] = child
            roots.append(child)
            stack[-1][2] += 1
            continue
        active.add(child_key)
        stack.append([child, child_args, 0, []])

    return value  # pragma: no cover - the root frame always returns above


def _same_frame_cell(cells):
    memo = {}
    roots = [_frame_cell_root(cell, memo=memo) for cell in cells]
    return (roots[0] if roots and all(root is roots[0] for root in roots[1:])
            else None)


def _resolve_frame(instruction, res):
    """The single frame answer for consumers with no phi home: the per-arm
    cells when they all agree, else None."""
    got = _frame_cells(instruction, res)
    if got is None:
        return None
    cells, _pending = got
    return _same_frame_cell(cells)


def _return_slot(instruction, index):
    if instruction is None or not hasattr(instruction, "slots"):
        return None
    return instruction.slots.get(index)


def _frame_home(instruction):
    return None if instruction is None else instruction.home


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


def walk_routine(body_list, entry, *, successors, initial_stack, exit_stacks,
                 execute_block, merge_value, extend_backedge,
                 orphan_stack=None, before_merge=None):
    """Run the shared CFG scheduler and top-aligned stack join for one routine.

    The stack *values* and phi representation deliberately stay caller-owned:
    ``merge_value`` receives ``(pred, present, value)`` arms and returns
    ``(stack_value, phi_token)``; ``extend_backedge`` completes that token once
    a loop's back edge has run.  This lets PySSA and pre-IR share the semantic
    decisions that used to drift — back-edge discovery, forward ordering,
    maximum-width joins and top alignment — without either representation
    depending on the other's value classes.

    ``execute_block(block, stack, predecessor_counts)`` mutates ``stack`` for
    the block's instructions. ``before_merge`` is an optional observer used by
    the lift to preserve its dead-underflow-edge repair; it cannot alter the
    merge.  The return value is the local predecessor-count map.
    """
    body = set(body_list)

    def local_successors(block):
        # Adapters may expose whole-program CFG successors. A routine walk must
        # never pull a callee or another owner's continuation into this frame.
        return tuple(succ for succ in successors(block) if succ in body)

    # Iterative DFS: real contracts contain control-flow chains deep enough to
    # make the formerly recursive lift walk hit Python's recursion limit.
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict = {}
    back: set = set()
    stack = [(entry, iter(local_successors(entry)))]
    color[entry] = GRAY
    while stack:
        block, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            color[block] = BLACK
            stack.pop()
            continue
        state = color.get(nxt, WHITE)
        if state == GRAY:
            back.add((block, nxt))
        elif state == WHITE:
            color[nxt] = GRAY
            stack.append((nxt, iter(local_successors(nxt))))

    back_targets = {dst for _, dst in back}
    fpred: dict = {b: [] for b in body_list}
    bpred: dict = {b: [] for b in body_list}
    for block in body_list:
        for succ in local_successors(block):
            (bpred if (block, succ) in back else fpred).setdefault(
                succ, []).append(block)

    order: list = []
    seen: set = {entry}
    stack = [(entry, iter(local_successors(entry)))]
    while stack:
        block, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            order.append(block)
            stack.pop()
            continue
        if (block, nxt) not in back and nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(local_successors(nxt))))
    order.reverse()
    # Disconnected/unorderable blocks still need their opcode operands marked;
    # their entry values come from the caller's explicit orphan policy.
    order += [b for b in body_list if b not in seen]

    npred = {
        b: len(fpred.get(b, ())) + len(bpred.get(b, ()))
        for b in body_list
    }
    pending: list = []                  # (phi token, top-first slot, back pred)
    orphan_stack = orphan_stack or (lambda _b: [])

    for block in order:
        preds = [p for p in fpred.get(block, ()) if p in exit_stacks]
        if block is entry:
            values = list(initial_stack)
        elif not preds:
            values = list(orphan_stack(block))
        elif len(preds) == 1 and not (
                block in back_targets and bpred.get(block)):
            values = list(exit_stacks[preds[0]])
        else:
            depth = max(len(exit_stacks[p]) for p in preds)
            is_loop = block in back_targets
            if before_merge is not None:
                before_merge(block, preds, depth, is_loop)
            values = []
            for bottom_index in range(depth):
                top_slot = depth - bottom_index
                incoming = [
                    (p, len(exit_stacks[p]) >= top_slot,
                     exit_stacks[p][-top_slot]
                     if len(exit_stacks[p]) >= top_slot else None)
                    for p in preds
                ]
                present = [value for _p, has_value, value in incoming
                           if has_value]
                if (not is_loop and len(present) == len(preds)
                        and all(value is present[0] for value in present)):
                    values.append(present[0])
                    continue
                value, token = merge_value(
                    block, top_slot, bottom_index, incoming, is_loop)
                values.append(value)
                if is_loop:
                    for pred in bpred.get(block, ()):
                        pending.append((token, top_slot, pred))
        execute_block(block, values, npred)
        exit_stacks[block] = values

    for token, top_slot, pred in pending:
        if pred not in exit_stacks:
            continue
        ex = exit_stacks[pred]
        present = len(ex) >= top_slot
        extend_backedge(token, pred, present,
                        ex[-top_slot] if present else None)
    return npred


def _run_routine(sub, body_list, res, arity, bb_to_sub, return_point,
                 retsubs, phi_factory, unsafe_callees=frozenset(),
                 deferred=None, proto_io=None, frame_instructions=None,
                 poisoned=frozenset(), effect_summaries=None):
    divergent = res.divergent
    body = set(body_list)
    nargs = arity.get(sub, (0, 0))[0]

    def merge_value(block, top_slot, bottom_index, incoming, _is_loop):
        ph = phi_factory(block, top_slot)
        ph.args.extend(value for _pred, present, value in incoming if present)
        if any(not present for _pred, present, _value in incoming):
            ph.partial = True
        res.phis.setdefault(block, []).append((bottom_index, ph))
        return ph, ph

    def extend_backedge(ph, _pred, present, value):
        if present:
            ph.args.append(value)
        else:
            # A net-popping lap lacks this cell. Omitting that arm would make
            # the forward value look definite on every iteration.
            ph.partial = True

    def execute_block(block, stack, npred):
        for op in block.ops:
            _exec(op, block, stack, nargs, res, bb_to_sub, retsubs, arity,
                  phi_factory, unsafe_callees, return_point, npred, deferred,
                  proto_io, divergent, frame_instructions, poisoned,
                  effect_summaries)

    walk_routine(
        body_list,
        sub,
        successors=lambda b: _isucc(b, body, return_point),
        initial_stack=[_Param(sub.key, i) for i in range(nargs)],
        exit_stacks=res.exit,
        execute_block=execute_block,
        merge_value=merge_value,
        extend_backedge=extend_backedge,
    )


def _exec(o, b, stack, nargs, res, bb_to_sub, retsubs, arity, phi_factory,
          unsafe_callees=frozenset(), return_point=None, npred=None,
          deferred=None, proto_io=None, divergent=frozenset(),
          frame_instructions=None, poisoned=frozenset(), effect_summaries=None):
    """One op against the clean stack, recording its operands TOP-FIRST."""
    if o.op in ("frame_dig", "frame_bury"):
        n = _imm_int(o)
        pos = None if n is None else nargs + n
        if bb_to_sub.get(b) in res.frame_skewed:
            # An earlier op in this routine dipped below the band; `stack[pos]`
            # would read/write a cell off by the underflow. Refuse honestly.
            if o.op == "frame_bury" and stack:
                stack.pop()
            res.unresolved.add(id(o))
            if o.op == "frame_dig":
                stack.append(None)
            return
        if b.key in poisoned:
            # The working list is NOT bottom-anchored here — that is what the
            # depth poison means: paths reach this block at different heights,
            # and the top-aligned merge realigned the shallower paths' cells.
            # ``stack[pos]`` would read the right cell on the deepest path and
            # a NEIGHBOURING cell on the others — the silent wrong-cell arm
            # this gate exists to stop. Frame positions are bottom-anchored
            # and lap-invariant, so the answer comes from frame-slot analysis
            # (:mod:`.frame_slots`): the region-entry snapshot for an untouched
            # position, the dominating write's operand for a buried one, and
            # an honest refusal for everything else.
            if o.op == "frame_bury":
                if not stack:
                    res.unresolved.add(id(o))
                    return
                v = stack.pop()
                res.args[id(o)] = [v]
                # The TARGET cell cannot be located in list coordinates, so
                # the deepest-path-aligned cell is REFUSED (writing the value
                # there is right on the deepest path and a wrong-cell write on
                # the others; leaving it untouched is stale on every path).
                # The HEIGHT bookkeeping mirrors the depth-known path exactly
                # — dropping the pos==len append silently shrank the list and
                # starved every later operand in the region (measured: +53
                # missing operands over the corpus). Reads of the buried slot
                # are answered by the plan's dominating-bury instruction.
                if pos is not None and 0 <= pos < len(stack):
                    stack[pos] = None
                elif pos is not None and pos == len(stack):
                    stack.append(None)
                else:
                    res.unresolved.add(id(o))
                return
            instruction = (frame_instructions.get(id(o))
                           if frame_instructions else None)
            got = _frame_cells(instruction, res, allow_pending=True)
            cell = None
            if got is not None:
                cells, pending_w = got
                same = _same_frame_cell(cells)
                if not pending_w and same is not None:
                    cell = same
                elif getattr(instruction, "allow_phi", True):
                    # Distinct arms (a loop-carried write merging with the
                    # entry value, or several per-path entry cells). Their
                    # true merge point is the REGION ENTRY — the loop header
                    # where laps join — so the phi is minted there; `mint`
                    # hands out a free slot, and the number is identity only
                    # (a poisoned block's top-slot arithmetic is exactly what
                    # the poison voids). A write the walk has not reached yet
                    # fills in afterwards, like recursion's deferred phis.
                    home = _frame_home(instruction)
                    ph = phi_factory(home, 1)
                    ph.args.extend(cells)
                    res.phis.setdefault(home, []).append(
                        (getattr(ph, "slot", 1), ph))
                    for wop in pending_w:
                        res.frame_deferred.append((ph, wop))
                    cell = ph
            if cell is not None:
                res.args[id(o)] = [cell]
                stack.append(o.outputs[0] if o.outputs else cell)
            else:
                res.unresolved.add(id(o))
                stack.append(None)
            return
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
        # entry slot of ours to hold the merge. A continuation may also be a
        # branch target: the factory allocates distinct identities for the
        # call-result merge and the subsequent control-flow join. Withdrawing
        # the call value here caused that join to keep only the direct branch
        # arm, sometimes folding an unknown returned value to a constant.
        can_merge = cont is not None and npred is not None and cont in npred
        if callee in unsafe_callees:
            # The callee reached below its own band with a PLAIN stack op, so
            # what sits underneath is whatever IT left — not what this routine
            # pushed. Where :mod:`.callee_effects` could hold the callee's
            # below-band effect EXACTLY (tree-shaped, callsub-free bodies —
            # every AVM stack op's effect is static, so the rewrite is a
            # computable function of the pre-call cells), the residual is
            # REWRITTEN through it: each touched depth gets the moved caller
            # cell, the call argument, or the callee-produced value that
            # really lands there, merged across retsub paths like the
            # divergent trail. Everything else falls back to the withdrawal:
            # blank the VALUES, keep the HEIGHT (the AVM re-checks the frame
            # bound at `retsub`, so a dipping callee must put the depth back).
            #
            # The UNSAFE set, deliberately WIDER than the lift's clobber-only
            # policy. Narrowing it to match the lift broke six invariants
            # (`below_frame_bury_is_dead`, `height_ambiguous_join`, three
            # frame-flow tests, the two-simulator alignment): the lift can fall
            # back on `Undefined`, but SSA-level may-analyses read these slots
            # DIRECTLY, so "could not verify the band height" has to withdraw
            # here or it reads as a resolved pre-call value. The remaining
            # refusals are honest, listed by `unresolved_call_results`.
            summary = (effect_summaries.get(callee)
                       if effect_summaries else None)
            if summary is None or summary.reach > len(stack):
                stack[:] = [None] * len(stack)
            else:
                base = list(stack)
                args_popped = res.args.get(id(o), ())
                for d in range(1, summary.reach + 1):
                    cells = []
                    for _rb, m in summary.paths:
                        c = m.get(d)
                        if c is None:
                            cells.append(base[-d])       # untouched this path
                        elif isinstance(c, _Below):
                            cells.append(base[-c.j]
                                         if c.j <= len(base) else None)
                        elif isinstance(c, _CalleeParam):
                            p = a_in - 1 - c.p           # args are TOP-FIRST
                            cells.append(args_popped[p]
                                         if 0 <= p < len(args_popped)
                                         else None)
                        else:
                            cells.append(c)              # callee-produced
                    if not cells or any(c is None for c in cells):
                        stack[-d] = None
                    elif len({id(c) for c in cells}) == 1:
                        stack[-d] = cells[0]
                    elif can_merge:
                        ph = phi_factory(cont, r_out + d)
                        ph.args.extend(cells)
                        res.phis.setdefault(cont, []).append((r_out + d, ph))
                        stack[-d] = ph
                    else:
                        stack[-d] = None
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
            vals, band_refused = [], False
            for rb in rets:
                if rb not in res.exit:
                    continue
                if a_proto is not None and rb.key in poisoned:
                    # A poisoned retsub's frame-slot read has the same
                    # wrong-cell risk as a frame_dig there (bottom-indexed in
                    # a bottom-unanchored list): frame-slot analysis answers, or the
                    # WHOLE slot refuses — the resolved subset would name the
                    # other paths' value as THE result. The plan may answer
                    # with one cell PER PATH into the retsub (five paths at
                    # five depths is one poisoned block, not five unknowns);
                    # this call site's continuation phi is their home.
                    ret = (frame_instructions.get(id(rb.ops[-1]))
                           if frame_instructions else None)
                    instr = _return_slot(ret, j)
                    got = _frame_cells(instr, res)
                    if got is None:
                        band_refused = True
                    else:
                        vals.extend(got[0])
                    continue
                if (a_proto is not None
                        and bb_to_sub.get(rb) in res.frame_skewed):
                    # This callee dipped below its band: its exit list is no
                    # longer frame-anchored, so `res.exit[rb][proto[0]+j]` is
                    # a wrong CELL, not a missing value.
                    v = None
                else:
                    v = _return_value(res.exit[rb], j, slot, a_proto)
                if v is not None:
                    vals.append(v)
                else:
                    # The resolved-subset trap: one unreadable retsub path
                    # plus one resolved path must NOT name the resolved one
                    # as THE result (same policy the `pending_rets` branch
                    # already enforces below).
                    band_refused = True
            if band_refused:
                pushes.append(None)
            elif pending_rets and (shifted
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
                # No caller-owned continuation or no returned values: there
                # is no valid home/evidence for a return merge.
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
    underflowed = False
    for _ in range(n_in):
        if stack:
            ins.append(stack.pop())
        else:
            ins.append(None)
            underflowed = True
    if underflowed:
        # This op dipped below the model's bottom: the pad keeps the walk
        # alive, but the list bottom no longer equals the frame base, so the
        # routine's bottom-anchored coordinates are poisoned from here on.
        routine = bb_to_sub.get(b)
        if routine is not None:
            res.frame_skewed.add(routine)
    if any(i is None for i in ins):
        res.unresolved.add(id(o))
    res.args[id(o)] = ins
    for v in reversed(o.outputs):
        stack.append(v)
