"""The two def-use edges PySSA leaves implicit — caller arg -> callee
``frame_dig`` param, and ``store N`` value -> ``load N`` output.

Subroutine arguments travel on the stack, and PySSA models ``frame_dig`` as an
opaque wide-stack read, so value flow dies at every call boundary until these
edges are added; unioning them makes a def-use analysis interprocedural with no
IR lift. Defined once here so the boolean taint engine, the byte-interval taint
and the taint graph cannot drift on what "reaches" means."""
from __future__ import annotations

from typing import Optional

from ..ssa import SSAProgram
from .frame_resolution import resolve, _proto_nargs


def frame_param_sources(prog: SSAProgram) -> dict:
    """``{frame_dig output SSAVar -> set(values bound to that param at every call site)}``.

    HAZARD: a ``callsub`` whose ``exit_stack`` is too shallow (PySSA caps the
    threaded stack at STACK_MAX) is skipped, so this may MISS a source — never
    invent a wrong one. Consumers must treat absence as unknown, not as clean."""
    out: dict = {}
    for sub, frames in resolve(prog).items():
        nargs: Optional[int] = _proto_nargs(sub.entry_bb)
        if not nargs or not frames.dig_param or not sub.callers:
            continue
        # param p (0 = deepest arg, nargs-1 = top) is the value at exit-stack slot
        # ``-(nargs - p)`` of each call site's callsub BB.
        param_args: dict = {p: set() for p in range(nargs)}
        for cs in sub.callers:
            es = getattr(cs.callsub_bb, "exit_stack", None)
            if not es or len(es) < nargs:
                continue                      # too-shallow / capped stack: skip
            for p in range(nargs):
                arg = es[-(nargs - p)]
                if arg is not None:
                    param_args[p].add(arg)
        for dig_out, p in frames.dig_param.items():
            srcs = param_args.get(p)
            if srcs:
                out.setdefault(dig_out, set()).update(srcs)
    return out


def frame_local_sources(prog: SSAProgram) -> dict:
    """``{frame_dig output SSAVar -> set(values a ``frame_bury`` put in that slot)}``.

    The other half of :func:`frame_param_sources`, and the half whose absence was
    unsound rather than merely imprecise. PySSA models a frame op as a wide band
    read, which over-approximates and is therefore safe — but only while the band
    is actually there. When the fat expansion cannot locate the band it falls back
    to the narrow arity, where ``frame_dig`` is ``(0, 1)``: an output with NO
    inputs. That is not a wider read, it is an EMPTY one, and a value with no
    incoming edge reads as clean to every may-analysis. Measured over 40 mainnet
    probes: 394 of 564 ``frame_dig`` reads of a local were disconnected that way,
    and unlike the param reads (509 of 530 rescued here) nothing reconnected them
    — so a value parked in a frame slot and read back lost its taint.

    Both halves of the edge were already computed and simply never joined:
    ``SubFrames.dig_local`` maps a read to its ``(slot, version)`` and
    ``SubFrames.bury`` maps each write to the version it opens. The value written
    is the burying op's ``inputs[0]`` — top-first, so that is the buried operand
    under the narrow arity and the band top under the fat one.

    Versions are matched EXACTLY rather than unioned across the slot. That is the
    same model the lift consumes (``lift._setup_frame`` reads ``dig_local``), and
    it is behaviourally verified against a live AVM, so it is a semantic answer
    and not an approximation that a may-consumer would need to widen."""
    out: dict = {}
    for sub, frames in resolve(prog).items():
        if not frames.dig_local or not frames.bury:
            continue
        buried: dict = {}                     # (slot, version) -> {values}
        for bb in sub.body:
            for a in bb.assignments:
                key = frames.bury.get(id(a))
                if key is None or not a.inputs:
                    continue
                v = a.inputs[0]               # top-first: the value being buried
                if v is not None:
                    buried.setdefault(key, set()).add(v)
        for dig_out, key in frames.dig_local.items():
            srcs = buried.get(key)
            if srcs:
                out.setdefault(dig_out, set()).update(srcs)
    return out


def frame_value_sources(prog: SSAProgram) -> dict:
    """``frame_param_sources`` unioned with :func:`frame_local_sources` — every
    value a ``frame_dig`` may read, wherever it came from.

    What a MAY consumer wants: a frame read is a frame read, and splitting the
    map by whether the slot happens to hold a parameter or a written local only
    invites using the half that is in scope. MUST consumers must NOT use this —
    ``security._value_flow`` needs the param set specifically, since "every
    caller pins this arg" is a different claim from "every write to this slot
    flows"."""
    out = {k: set(v) for k, v in frame_param_sources(prog).items()}
    for k, v in frame_local_sources(prog).items():
        out.setdefault(k, set()).update(v)
    return out


def scratch_load_sources(prog: SSAProgram) -> dict:
    """``{load N output SSAVar -> [store N value SSAVars that may reach it]}``.

    HAZARD: MAY semantics. The union over reaching stores over-approximates,
    which is sound for taint. Sentinel reaching-defs (zero-init pseudo-store,
    unresolvable store, dynamic ``stores``) resolve to no SSAVar and vanish
    here, so a MUST-style consumer using this map silently misses them and
    concludes too much — such consumers must read ``_scratch_influence``
    directly, where the sentinel is still visible to bail on."""
    prog._ensure_scratch_influence()
    out: dict = {}
    graph = getattr(prog, "_graph", None)
    if graph is None:
        return out
    for n in graph.nodes:
        stores = graph.nodes[n].get("scratch_stores")
        if not stores:
            continue
        loc = getattr(n, "location", None)
        if loc is None:
            continue
        load_var = prog.var(loc.file, loc.start_line, 1)
        if load_var is None:
            continue
        srcs = [sv for (sf, sl, si) in stores
                if (sv := prog.var(sf, sl, si)) is not None]
        if srcs:
            out.setdefault(load_var, []).extend(srcs)
    return out
