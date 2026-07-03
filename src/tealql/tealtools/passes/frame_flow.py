"""Interprocedural frame dataflow — the caller-arg -> callee-param edges the base
PySSA def-use relation leaves implicit.

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
