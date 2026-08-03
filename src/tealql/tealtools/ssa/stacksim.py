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


def infer_arities(blocks, bb_to_sub, proto_io, return_point) -> dict:
    """``sub entry -> (nargs, nret)``, read off ``proto`` or inferred.

    A pre-``proto`` sub declares nothing: its args and results are just stack
    depth, so they are recovered by the same cross-procedural depth fixpoint the
    lift uses (``lift._infer_arities``) — how far below its entry the body dips
    is how many arguments it took, and what it leaves at ``retsub`` above that
    floor is what it returned. Without this a legacy callee reads as ``(0, 0)``
    and its arguments are left sitting on the CALLER's stack, so the caller's
    next op consumes the value pushed BEFORE the call instead of the call's
    result."""
    subs = [b for b in blocks if bb_to_sub.get(b) is b]
    arity = {s: proto_io.get(s, (0, 0)) for s in subs}
    bodies: dict = {}
    for b in blocks:
        bodies.setdefault(bb_to_sub.get(b), []).append(b)

    for _ in range(len(subs) + 4):
        changed = False
        for s in subs:
            if s in proto_io:
                continue
            body = set(bodies.get(s, ()))
            depth = {s: 0}
            order = [s]
            floor = 0
            ret_ds: list = []
            i = 0
            while i < len(order):
                b = order[i]
                i += 1
                d = mn = depth[b]
                for o in b.ops:
                    if o.op == "retsub":
                        break
                    if o.op == "callsub":
                        pop, push = arity.get(_callee_of(b, bb_to_sub), (0, 0))
                    else:
                        pop, push = _narrow(o)
                    d -= pop
                    mn = min(mn, d)
                    d += push
                floor = min(floor, mn)
                if b.ops and b.ops[-1].op == "retsub":
                    ret_ds.append(d)
                for su in _isucc(b, body, return_point):
                    if su not in depth:
                        depth[su] = d
                        order.append(su)
            # MAX over ALL retsub sites: a sub whose paths diverge would
            # otherwise silently truncate a deeper path's returns.
            ret_d = max(ret_ds) if ret_ds else None
            na, nr = -floor, (ret_d - floor if ret_d is not None else 0)
            if arity[s] != (na, nr):
                arity[s] = (na, nr)
                changed = True
        if not changed:
            break
    return arity


class _Result:
    """What one simulation produced.

    ``args``  — ``id(PyOp) -> [operand]``, TOP-FIRST, matching ``PyOp.inputs``.
    ``phis``  — ``PyBlock -> [(slot, PyPhi)]`` merges created at joins.
    ``exit``  — ``PyBlock -> [operand]`` bottom-first, for the differential only.
    ``unresolved`` — ops the sim could not give a full operand list.
    """

    __slots__ = ("args", "phis", "exit", "unresolved")

    def __init__(self):
        self.args: dict = {}
        self.phis: dict = {}
        self.exit: dict = {}
        self.unresolved: set = set()


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
             *, bind_params: bool = True) -> "_Result":
    """Simulate every routine and return a :class:`_Result`.

    ``phi_factory(block, slot) -> phi`` mints the merge value, so the caller
    decides what a phi IS (a ``PyPhi`` in the builder, a stand-in in a test).

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
    # stack — which the caller's next op then consumes.
    arity = infer_arities(blocks, bb_to_sub, proto_io, return_point)
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
    for sub in _callee_first(by_sub, bb_to_sub):
        _run_routine(sub, by_sub[sub], res, arity, bb_to_sub, return_point,
                     retsubs, phi_factory)
    if bind_params:
        _bind_params(blocks, res, arity, bb_to_sub, phi_factory)
    return res


def _callee_first(by_sub, bb_to_sub):
    """Routine entries ordered so a callee precedes its callers.

    Recursion has no such order, so a cycle is emitted in discovery order and
    its self-referential call results stay unresolved — honest, and the only
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
            if len(vals) == 1:
                bound[key] = vals[0]
            elif vals:
                ph = phi_factory(sub, a_in - i)
                bound[key] = ph
                ph.args.extend(vals)

    def resolve(v, depth=0):
        while isinstance(v, _Param) and depth < 16:
            nxt = bound.get((v.sub_key, v.index))
            if nxt is None or nxt is v:
                return None                # no call site supplies it
            v, depth = nxt, depth + 1
        return v

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


def _isucc(b, body, return_point):
    """Successors INSIDE the routine: a call flows to its continuation, never
    into the callee, and a return leaves."""
    if b.ops and b.ops[-1].op in ("retsub", "return", "err"):
        return []
    if b.ops and b.ops[-1].op == "callsub":
        cont = return_point.get(b)
        return [cont] if cont is not None and cont in body else []
    return [s for s in b.succs if s in body]


def _run_routine(sub, body_list, res, arity, bb_to_sub, return_point,
                 retsubs, phi_factory):
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

    pending: list = []
    for b in order:
        preds = [p for p in fpred.get(b, ()) if p in res.exit]
        stack = _entry_stack(b, sub, nargs, preds, back_targets,
                             bpred.get(b, ()), pending, res, phi_factory)
        for o in b.ops:
            _exec(o, b, stack, nargs, res, bb_to_sub, retsubs, arity, phi_factory)
        res.exit[b] = stack
    for ph, slot, bp in pending:
        if bp in res.exit and slot < len(res.exit[bp]):
            ph.args.append(res.exit[bp][slot])


def _entry_stack(b, entry, nargs, preds, back_targets, bpred_b, pending,
                 res, phi_factory):
    if b is entry or not preds:
        return [_Param(entry.key, i) for i in range(nargs)]
    if b in back_targets:
        depth = min(len(res.exit[p]) for p in preds)
        stack, phis = [], []
        for slot in range(depth):
            ph = phi_factory(b, depth - slot)
            ph.args.extend(res.exit[p][slot] for p in preds)
            phis.append((slot, ph))
            stack.append(ph)
            for bp in bpred_b:
                pending.append((ph, slot, bp))
        res.phis[b] = phis
        return stack
    if len(preds) == 1:
        return list(res.exit[preds[0]])
    depth = min(len(res.exit[p]) for p in preds)
    stack, phis = [], []
    for slot in range(depth):
        vals = [res.exit[p][slot] for p in preds]
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


def _exec(o, b, stack, nargs, res, bb_to_sub, retsubs, arity, phi_factory):
    """One op against the clean stack, recording its operands TOP-FIRST."""
    if o.op in ("frame_dig", "frame_bury"):
        n = _imm_int(o)
        pos = None if n is None else nargs + n
        if o.op == "frame_dig":
            if pos is not None and 0 <= pos < len(stack):
                res.args[id(o)] = []
                stack.append(stack[pos])
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
        for j in range(r_out):
            slot = r_out - j                      # top-first within the returns
            vals = [res.exit[rb][-slot] for rb in rets
                    if rb in res.exit and len(res.exit[rb]) >= slot]
            if len(vals) == 1:
                stack.append(vals[0])
            elif vals:
                ph = phi_factory(b, slot)
                ph.args.extend(vals)
                res.phis.setdefault(b, []).append((-1, ph))
                stack.append(ph)
            else:
                stack.append(None)
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
