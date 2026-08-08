"""Resolve each ``frame_dig`` / ``frame_bury`` to its logical param or versioned
local — an opt-in layer over PySSA's conservative fat-frame substrate.

Exact rather than heuristic for ``proto`` subroutines, where the AVM frame layout
is declared. Legal legacy subroutines can also use frame ops; the lift invokes
``resolve_sub`` with their inferred argument band, while the public annotation
pass below stays restricted to declared frames. The substrate keeps modelling
them as wide stack ops so may-analyses remain sound."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..ssa import SSAVar
from ..ssa.operands import imm0 as _imm0


@dataclass
class SubFrames:
    """One subroutine's frame-slot model, in SSA vars and ints (no IR registers)."""
    dig_param: dict = field(default_factory=dict)    # frame_dig out0 -> param index
    dig_local: dict = field(default_factory=dict)    # frame_dig out0 -> (slot, version)
    bury: dict = field(default_factory=dict)         # id(frame_bury) -> (slot, version)
    passthrough: dict = field(default_factory=dict)  # fat-frame out -> source operand
    final: dict = field(default_factory=dict)        # slot -> final version
    pushed: set = field(default_factory=set)         # frame_dig out0 of a k>=0 pushed
    #   local resolved to its band target; the resim must route these through
    #   value() too — see lift._setup_frame / _build_block.
    pushed_slot: dict = field(default_factory=dict)  # pushed frame_dig out0 -> slot k,
    #   so the resim can prefer the LIVE slot value at stack depth len(params)+k:
    #   the band `a.inputs[-1]` is polluted by a loop's band phis, which made a
    #   frame_dig of a pre-loop local return the loop's mutated register.


def resolve_sub(blocks, nargs: int) -> SubFrames:
    """Resolve one subroutine's frames.

    ``frame_dig -k`` with k inside the proto args reads param ``nargs - k``;
    every other frame op reads/writes a versioned local (each bury opens a
    version, each read takes the version reaching it in block order)."""
    res = SubFrames()
    cur: dict = {}                           # slot -> current version
    nextver: dict = {}                       # slot -> next version

    # HAZARD: a param slot stops being "the incoming arg" once a `frame_bury`
    # writes it, and that must be decided on CFG order — a dig of slot k is a
    # param read only if NO bury of k can REACH it. Source order is wrong for a
    # loop (`while ...: i += 1` buries slot -k later in source but earlier in
    # execution), which misclassifies the loop-head dig as a clean param read;
    # `frame_flow.frame_param_sources` then reports the caller's args as its
    # complete sources and a must-consumer credits a caller pin to a loop-mutated
    # local, suppressing a real finding.
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

    _burys: dict = {}                        # slot -> [(block, op_index)]
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
                    # A param slot still holding the incoming arg; once buried
                    # it is a mutable local and falls through below.
                    res.dig_param[out0] = nargs + k
                else:
                    v = cur.get(k)
                    if v is not None:
                        res.dig_local[out0] = (k, v)          # a `frame_bury`-d local
                    elif k >= 0 and a.inputs:
                        # A pushed local (slot ABOVE the frame base) was placed
                        # there by a stack op this slot/version model doesn't
                        # track, so route out0 to the band target rather than an
                        # l%slot version no write defines. inputs are TOP-FIRST,
                        # so the band target is the DEEPEST input, `inputs[-1]`.
                        # k>=0 only: resolving below-frame reads this way diverges
                        # from the IR path.
                        res.passthrough[out0] = a.inputs[-1]
                        res.pushed.add(out0)
                        res.pushed_slot[out0] = k
                    else:
                        res.dig_local[out0] = (k, v if v is not None else fresh(k))
                for i in range(1, len(a.outputs)):   # dig: out[i] = in[i-1]
                    o = a.outputs[i]
                    if isinstance(o, SSAVar) and i - 1 < len(a.inputs):
                        res.passthrough[o] = a.inputs[i - 1]
            elif a.op == "frame_bury":
                k = _imm0(a)
                if k is not None:
                    # HAZARD: version EVERY bury, including a param slot (k < 0)
                    # and one with no SSA inputs. Each write must open a fresh
                    # version or the lift emits one register assigned many times
                    # (Puya rejects it). A bury of a value the base SSA doesn't
                    # carry on the stack — e.g. a `callsub` return, which the
                    # resim threads — still writes the slot; skipping it leaves
                    # the slot unversioned and a later `frame_dig` is then
                    # misclassified as a pushed local and reads the wrong register.
                    res.bury[id(a)] = (k, fresh(k))
                for i in range(len(a.outputs)):      # bury: out[i] = in[i+1]
                    o = a.outputs[i]
                    if isinstance(o, SSAVar) and i + 1 < len(a.inputs):
                        res.passthrough[o] = a.inputs[i + 1]
    res.final = dict(cur)
    return res


def _proto_nargs(entry_bb) -> int | None:
    """Arg count from a sub entry's ``proto A R``, or None for a legacy non-proto sub."""
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
