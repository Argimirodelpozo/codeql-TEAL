"""An upper bound on the AVM value-stack depth, for the overflows the lift cannot see.

The AVM fails any op that leaves more than 1000 values on the stack (eval.go
``maxStackDepth``). The lift checks that limit where it knows the depth exactly: in the
main program from its first instruction, and in a subroutine from its frame. Two depths
it cannot see:

- a CALL puts the caller's residual under the callee's frame, so a callee that stays
  under 1000 on its own can still overflow (and recursion can grow that residual);
- after a join that merges different depths, the depth is one of several.

:func:`stack_depth_bound` bounds the depth any execution can reach, from the canonical
stack model the SSA builder computed (``SSAProgram._pyssa``: routine ownership, proto
and inferred arities, verified call/return pairs): a forward walk per routine taking the
MAX at joins, then a fixpoint over the call graph. A bound of at most 1000 proves no
execution overflows; past it (a stack that grows in a loop or through recursion
eventually is) the consumer must account for an overflow it may not be modelling.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_STACK_DEPTH = 1000          # eval.go maxStackDepth


@dataclass(frozen=True)
class StackDepthBound:
    """``bound``: an upper bound on the stack depth any execution reaches, or None when
    none was established at or below the limit -- ``reason`` says why (a growing stack,
    or a part of the program the stack model could not anchor)."""
    bound: int | None
    reason: str = ""

    @property
    def may_overflow(self) -> bool:
        return self.bound is None or self.bound > MAX_STACK_DEPTH


def _net(op) -> int:
    if op.op == "frame_dig":
        return 1
    if op.op == "frame_bury":
        return -1
    return op.n_out - op.n_in


def stack_depth_bound(prog) -> StackDepthBound:
    """Bound the stack depth of every execution of ``prog`` (see the module docstring).
    Depths are bottom-anchored per routine (a subroutine's entry depth is its argument
    count); a call at depth ``h`` into a callee taking ``A`` arguments reaches
    ``h - A + need(callee)``."""
    py = getattr(prog, "_pyssa", None)
    if py is None or not py.blocks:
        return StackDepthBound(None, "no canonical stack model")
    owner = py._bb_to_sub
    pairs = py._pair_by_cs
    arity = {**py._callsub_arities, **py._proto_io}         # a proto declaration wins
    over = MAX_STACK_DEPTH + 1                              # nothing past this matters

    bodies: dict = {}
    for block in py.blocks:
        if owner.get(block) is not None:
            bodies.setdefault(owner[block], []).append(block)
    returns = {r for r, body in bodies.items()
               if any(b.ops and b.ops[-1].op == "retsub" for b in body)}

    def walk(routine, entry_depth):
        """(local peak, [(depth at call, callee args, callee)]) or (None, reason)."""
        depth_in = {routine: entry_depth}
        work, peak, sites = [routine], entry_depth, {}
        while work:
            block = work.pop()
            d = depth_in[block]
            for op in block.ops:
                if op.op == "callsub":                      # the block's last op
                    callee = next((s for s in block.succs if owner.get(s) is s), None)
                    if callee is None or callee not in arity:
                        return None, "a call whose callee's arity is unknown"
                    sites[block] = (d, arity[callee][0], callee)
                    break
                d += _net(op)
                peak = max(peak, d)
            if peak > over:
                return peak, []                             # already past the limit
            if block.ops and block.ops[-1].op == "callsub":
                pair = pairs.get(block)
                if pair is None:
                    if sites[block][2] in returns:
                        return None, "a call whose return depth is not anchored"
                    continue                                # the callee never returns
                cont, a, r = pair
                nexts = [(cont, d - a + r)]
            elif block.ops and block.ops[-1].op == "retsub":
                nexts = []
            else:
                # every plain successor, owned or not: a shared tail another routine
                # owns still runs on THIS stack (the dip follows control, not ownership)
                nexts = [(s, d) for s in block.succs]
            for succ, proposed in nexts:
                if succ not in depth_in or proposed > depth_in[succ]:
                    depth_in[succ] = proposed               # MAX at a join
                    work.append(succ)
        return peak, list(sites.values())

    entry = min(py.blocks, key=lambda b: b.key)
    main = owner.get(entry)
    if main is None:
        return StackDepthBound(None, "the program's first block has no routine")

    local: dict = {}
    sites: dict = {}
    todo = [main]
    while todo:                                             # routines reachable from main
        routine = todo.pop()
        if routine in local:
            continue
        start = 0 if routine is main else arity.get(routine, (0, 0))[0]
        peak, found = walk(routine, start)
        if peak is None:
            return StackDepthBound(None, found)
        local[routine], sites[routine] = peak, found
        todo.extend(callee for _, _, callee in found)

    need = dict(local)
    changed = True
    while changed:                                          # monotone, capped at `over`
        changed = False
        for routine, calls in sites.items():
            for h, args, callee in calls:
                reach = min(h - args + need[callee], over)
                if reach > need[routine]:
                    need[routine] = reach
                    changed = True
    if need[main] > MAX_STACK_DEPTH:
        return StackDepthBound(None, "the stack can pass 1000 values")
    return StackDepthBound(need[main])
