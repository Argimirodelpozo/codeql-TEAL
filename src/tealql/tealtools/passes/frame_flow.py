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
