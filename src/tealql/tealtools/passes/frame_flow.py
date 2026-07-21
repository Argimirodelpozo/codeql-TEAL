"""The def-use edges the base PySSA relation leaves implicit — the shared
bridges every taint-style analysis needs.

Two of them, both "this value has no def-use input, but a value does flow into
it": :func:`frame_param_sources` (caller arg -> callee ``frame_dig`` param) and
:func:`scratch_load_sources` (``store N`` value -> ``load N`` output). The
boolean taint engine, the byte-interval taint and the taint graph each used to
rebuild these independently; they are one definition here so the three cannot
drift apart on what "reaches" means.

--- interprocedural frame dataflow ---

Algorand subroutines pass arguments on the STACK: the caller pushes values, then
``callsub`` transfers control, and the callee reads each parameter with
``frame_dig`` (a frame-relative read). PySSA models ``frame_dig`` as an opaque
wide-stack read (no def-use input — the conservative "fat-frame" substrate), so
taint / const / range stop at the call boundary. The precise resolution exists
though: :mod:`tealql.tealtools.passes.frame_resolution` maps each ``frame_dig`` to its
param index, and :attr:`BasicBlock.exit_stack` gives the stack at a ``callsub``.

:func:`frame_param_sources` stitches those into the missing edges:

    frame_dig (reads param p of sub S)  <-  the value bound to param p at every
                                            call site of S (its callsub BB's
                                            exit-stack slot)

A def-use / taint analysis that unions a ``frame_dig`` output's taint from these
sources becomes interprocedural natively — no IR lift needed. Sound for the
common case; a ``callsub`` whose ``exit_stack`` is too shallow (PySSA caps the
threaded stack at STACK_MAX on very deep stacks — the only place the lift's
re-sim is strictly more precise) is skipped conservatively (a may-FN, never a
wrong edge).
"""
from __future__ import annotations

from typing import Optional

from ..ssa import SSAProgram
from .frame_resolution import resolve, _proto_nargs


def frame_param_sources(prog: SSAProgram) -> dict:
    """``{frame_dig output SSAVar -> set(caller-arg operands)}``.

    For each ``proto`` subroutine, each ``frame_dig`` that reads a parameter is
    mapped to the set of values bound to that parameter across all of the sub's
    call sites. Empty for a program with no ``proto`` subs / no callers."""
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

    Scratch is written by ``store N`` (which has no SSA output) and read by
    ``load N`` (which has no SSA input), so the base def-use relation drops the
    connection entirely and taint dies at any ``store N; …; load N`` round trip.
    The ``scratch_stores`` graph annotation
    (:func:`tealql.tealtools.ssa.scratch_influence.compute_scratch_influence`)
    supplies the reaching-definition answer; this resolves those keys to the
    actual value SSAVars.

    MAY semantics: the union over every reaching store is a sound
    over-approximation. Sentinel reaching-defs (the zero-init pseudo-store, an
    unresolvable store, a dynamic ``stores``) resolve to no SSAVar and are
    simply absent here — correct for a may-union consumer, and the reason
    must-style consumers must read ``_scratch_influence`` directly rather than
    this map (they have to SEE the sentinel in order to bail on it)."""
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
