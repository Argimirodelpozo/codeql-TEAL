"""Precise frame-slot resolution — an opt-in layer over PySSA's conservative
fat-frame model (which stays the sound substrate for the may-analyses).

`frame_dig`/`frame_bury` only occur in `proto` subroutines, where the AVM frame
layout is exact, so resolving each to its logical param / versioned local is
*sound*, not heuristic. PySSA keeps modelling them as wide stack ops (so taint /
const / range carry through conservatively); consumers wanting precision read the
per-op slot model here instead, leaving the substrate untouched.

`resolve_sub(blocks, nargs)` is the core (a sub's blocks + its proto arg count);
`resolve(prog)` partitions via `structure.analyze_structure` and resolves every
proto sub.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..ssa import SSAVar


def _imm0(a) -> int | None:
    toks = (a.immediates or "").split()
    try:
        return int(toks[0]) if toks else None
    except ValueError:
        return None


@dataclass
class SubFrames:
    """One subroutine's frame-slot model — substrate-level (SSA vars + ints, no
    IR registers): which param / versioned local each frame op accesses, plus the
    fat-frame band passthrough."""
    dig_param: dict = field(default_factory=dict)    # frame_dig out0 -> param index
    dig_local: dict = field(default_factory=dict)    # frame_dig out0 -> (slot, version)
    bury: dict = field(default_factory=dict)         # id(frame_bury) -> (slot, version)
    passthrough: dict = field(default_factory=dict)  # fat-frame out -> source operand
    final: dict = field(default_factory=dict)        # slot -> final version
    pushed: set = field(default_factory=set)         # frame_dig out0 of a k>=0 pushed
    #   local resolved to its band target (vs an orphan); the resim path must
    #   route these through value() too — see lift._setup_frame / _build_block.


def resolve_sub(blocks, nargs: int) -> SubFrames:
    """Resolve one subroutine's frames: ``frame_dig -k`` (k in proto args) reads
    param ``nargs-k``; other ``frame_dig``/``frame_bury`` read/write a versioned
    local (each bury opens a version, each read takes the version reaching it in
    block order). Also routes the fat-frame band passthrough (out[i] = in[i∓1])."""
    res = SubFrames()
    cur: dict = {}                           # slot -> current version
    nextver: dict = {}                       # slot -> next version

    # A param slot stops being "the incoming arg" once a `frame_bury` writes
    # it. Deciding that from SOURCE order alone (has a bury been *scanned*
    # yet?) is wrong for a loop: `def f(i): while ...: i += 1` buries slot -k
    # in the body, which is LATER in source but EARLIER in execution for every
    # iteration after the first, so the loop-head dig was misclassified as a
    # clean param read. `frame_flow.frame_param_sources` then reported the
    # CALLER's args as that value's complete sources, and a must-style
    # consumer (security/_value_flow's pin propagation) could credit a
    # caller pin to a loop-mutated local and suppress a finding.
    #
    # Decide it on CFG order instead: a dig of slot k is a param read only if
    # NO bury of k can reach it.
    _in_sub = {id(b) for b in blocks}
    _fwd: dict = {}

    def _reaches_block(src, dst) -> bool:
        """Is ``dst`` reachable from ``src`` over CFG edges inside this sub?"""
        seen = _fwd.get(id(src))
        if seen is None:
            seen, stack = set(), [src]
            while stack:
                b = stack.pop()
                for s in getattr(b, "successors", ()) or ():
                    if id(s) in _in_sub and id(s) not in seen:
                        seen.add(id(s))
                        stack.append(s)
            _fwd[id(src)] = seen
        return id(dst) in seen

    # slot -> [(block, op_index)] for every frame_bury of that slot.
    _burys: dict = {}
    for _bb in blocks:
        for _i, _a in enumerate(_bb.assignments):
            if _a.op == "frame_bury":
                _k = _imm0(_a)
                if _k is not None:
                    _burys.setdefault(_k, []).append((_bb, _i))

    def _bury_reaches(slot: int, bb, idx: int) -> bool:
        """Can any `frame_bury slot` reach the dig at ``(bb, idx)``?"""
        for (wbb, widx) in _burys.get(slot, ()):
            if wbb is bb:
                if widx < idx or _reaches_block(bb, bb):   # or around a loop
                    return True
            elif _reaches_block(wbb, bb):
                return True
        return False

    def fresh(slot: int) -> int:
        v = nextver.get(slot, 0)
        nextver[slot] = v + 1
        cur[slot] = v
        return v

    for bb in blocks:
        for op_i, a in enumerate(bb.assignments):
            if a.op == "frame_dig" and a.outputs:
                k = _imm0(a)
                if k is None:
                    continue
                out0 = a.outputs[0]
                if (-nargs <= k <= -1 and k not in cur
                        and not _bury_reaches(k, bb, op_i)):
                    # A param slot, still holding the incoming arg. Once it has
                    # been `frame_bury`-d (k in cur) it is a mutable local from
                    # that point on, so fall through to the versioned-local read.
                    res.dig_param[out0] = nargs + k
                else:
                    v = cur.get(k)
                    if v is not None:
                        res.dig_local[out0] = (k, v)          # a `frame_bury`-d local
                    elif k >= 0 and a.inputs:
                        # A pushed local (slot ABOVE the frame base) never written
                        # by `frame_bury`: its value was placed on the frame by a
                        # *stack* op (`bury`/`dup`/push) this slot/version model
                        # doesn't track. The dug value is the slot's current stack
                        # value = the band target (deepest input; _try_expand_frame_op
                        # lays inputs top-first). Route out0 there instead of an
                        # l%slot version no write defines (the cross-block orphan).
                        # k>=0 ONLY: negative below-frame reads keep prior behavior
                        # (resolving them via value() diverges from the IR path).
                        res.passthrough[out0] = a.inputs[-1]
                        res.pushed.add(out0)
                    else:
                        res.dig_local[out0] = (k, v if v is not None else fresh(k))
                for i in range(1, len(a.outputs)):   # dig: out[i] = in[i-1]
                    o = a.outputs[i]
                    if isinstance(o, SSAVar) and i - 1 < len(a.inputs):
                        res.passthrough[o] = a.inputs[i - 1]
            elif a.op == "frame_bury":
                k = _imm0(a)
                if k is not None:
                    # Version EVERY bury, including a param slot (k < 0): writing
                    # it turns that slot into a mutable local, and each write must
                    # open a fresh SSA version or the lift emits one register
                    # assigned many times (Puya rejects it as an SSA violation).
                    #
                    # Open the version EVEN with no SSA inputs: a `frame_bury` of
                    # a value the base SSA doesn't carry on the stack -- e.g. a
                    # `callsub` return (callsub has 0 SSA outputs; the resim
                    # threads the return) -- still writes the slot. The old
                    # `and a.inputs` guard skipped it, leaving the slot
                    # unversioned, so a later `frame_dig` of that slot was
                    # MISCLASSIFIED as a *pushed* local (cur.get(k) is None) and
                    # routed to the stack-band value (the wrong register) instead
                    # of `dig_local`. The resim writes the threaded value into the
                    # slot, so versioning the bury makes the dig read it.
                    res.bury[id(a)] = (k, fresh(k))
                for i in range(len(a.outputs)):      # bury: out[i] = in[i+1]
                    o = a.outputs[i]
                    if isinstance(o, SSAVar) and i + 1 < len(a.inputs):
                        res.passthrough[o] = a.inputs[i + 1]
    res.final = dict(cur)
    return res


def _proto_nargs(entry_bb) -> int | None:
    """Arg count from a sub entry's ``proto A R`` op, or None for a legacy
    non-proto sub (which has no frame ops)."""
    for a in entry_bb.assignments:
        if a.op == "proto":
            toks = (a.immediates or "").split()
            try:
                return int(toks[0]) if toks else 0
            except ValueError:
                return 0
    return None


def resolve(prog) -> dict:
    """``{structure.Subroutine: SubFrames}`` for every proto subroutine."""
    from ..structure import analyze_structure
    out: dict = {}
    for s in analyze_structure(prog).subroutines:
        nargs = _proto_nargs(s.entry_bb)
        if nargs is not None:                # skip legacy non-proto (no frame ops)
            out[s] = resolve_sub(sorted(s.body, key=lambda bb: (bb.file, bb.first_line)),
                                 nargs)
    return out
