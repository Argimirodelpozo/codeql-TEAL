"""The def-use edges PySSA leaves implicit — caller arg -> callee ``frame_dig``
param, ``store N`` value -> ``load N`` output, and callee ``retsub`` value ->
the caller's continuation.

Subroutine arguments travel on the stack, and PySSA models ``frame_dig`` as an
opaque wide-stack read, so value flow dies at every call boundary until these
edges are added; unioning them makes a def-use analysis interprocedural with no
IR lift. Defined once here so the boolean taint engine, the byte-interval taint
and the taint graph cannot drift on what "reaches" means.

Each edge has a companion that ENUMERATES what it could not resolve
(:func:`frame_unresolved_reads`, :func:`unresolved_call_results`). That is the
project rule applied to dataflow: "0 findings because nothing could be resolved"
must never read the same as "0 findings because it is clean"."""
from __future__ import annotations

import logging
from typing import Optional

from ..ssa import SSAProgram
from .frame_resolution import resolve, _proto_nargs

logger = logging.getLogger("tealql.tealtools.passes.frame_flow")


def frame_param_sources(prog: SSAProgram) -> dict:
    """``{frame_dig output SSAVar -> set(values bound to that param at every call site)}``.

    The arguments are the ``callsub``'s OWN operands, TOP-FIRST — so param ``p``
    (0 = deepest, nargs-1 = top) is ``inputs[nargs - 1 - p]``.

    It used to read them off ``callsub_bb.exit_stack`` instead, which held them
    only while a ``callsub`` was modelled as consuming nothing. Now that the
    stack model knows what a call does, that slot is the call's RESULT or the
    caller's residual: measured over 15 probes, 333 of 342 entries named the
    wrong value or none. A param source is consumed by MUST reasoning
    (``security._value_flow``: "every caller pins this arg"), where a wrong
    value is worse than a missing one.

    HAZARD: a ``callsub`` whose operand list is short — an argument the
    simulation could not resolve is dropped by ``_build_assignments``, and index
    ``nargs - 1 - p`` would then name a different argument — is SKIPPED. This may
    MISS a source, never invent one. Consumers must treat absence as unknown,
    not as clean."""
    out: dict = {}
    for sub, frames in resolve(prog).items():
        nargs: Optional[int] = _proto_nargs(sub.entry_bb)
        if not nargs or not frames.dig_param or not sub.callers:
            continue
        param_args: dict = {p: set() for p in range(nargs)}
        for cs in sub.callers:
            bb = cs.callsub_bb
            call = next((a for a in reversed(getattr(bb, "assignments", ()))
                         if a.op == "callsub"), None)
            if call is None or len(call.inputs) != nargs:
                continue                      # unresolved operand: skip, never guess
            for p in range(nargs):
                arg = call.inputs[nargs - 1 - p]
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


def frame_unresolved_reads(prog: SSAProgram) -> list:
    """The ``frame_dig`` assignments this layer CANNOT give a source — the
    irreducible blind spot, listed rather than left silent.

    Each is a read of a local (``N >= 0``) that carries no band (narrow fallback,
    so no inputs) and that the source maps could not connect to anything. Two
    causes, both ending in the same place:

    * the slot holds a PUSHED local — no ``frame_bury`` ever wrote it, the value
      was left there by ordinary stack traffic;
    * a bury DID write it, but of a value the base SSA does not carry on the stack
      — a ``callsub`` return, which only the lift's re-simulation threads, so the
      burying op has no inputs to take the value from.

    Either way the value sits at band position ``nargs + N``, and finding it needs
    the band arithmetic the narrow fallback could not do: the position follows
    from a routine-relative depth, and phase 6c cannot compute one for a block
    after a ``callsub`` — the continuation is reached along the callee's ``retsub``
    edge, and no depth is consistent with a stack model that gives ``callsub``
    arity ``(0, 0)``. Closing it means teaching that model what a call does.

    Measured over the 231 distinct mainnet probes: 43 of 1580 narrow local reads
    (2.7%), in 5 contracts. Each reads as CLEAN to a may-analysis, so a value
    reaching one is a possible false negative — hence enumerable here rather than
    merely absent from the source maps. Deliberately NOT filtered by whether a
    bury nominally exists: the callsub-return case has a bury and is still
    invisible, and it is the case with a demonstrated taint path behind it."""
    covered: set = set()
    for m in (frame_param_sources(prog), frame_local_sources(prog)):
        covered |= {id(k) for k in m}
    out: list = []
    for a in prog.assignments:
        if a.op != "frame_dig" or a.inputs or not a.outputs:
            continue
        try:
            n = int(str(a.immediates).strip().split()[0])
        except (ValueError, IndexError):
            continue
        if n >= 0 and id(a.outputs[0]) not in covered:
            out.append(a)
    return out


def _proto_nret(entry_bb) -> "Optional[int]":
    """Return count from a sub entry's ``proto A R``, or None for a legacy sub."""
    for a in entry_bb.assignments:
        if a.op == "proto":
            toks = (a.immediates or "").split()
            try:
                return int(toks[1]) if len(toks) > 1 else 0
            except ValueError:
                return 0
    return None


def unresolved_call_results(prog: SSAProgram) -> list:
    """``[(callsub Assignment, slot)]`` for every declared result a call did NOT
    produce a value for — the call-boundary twin of
    :func:`frame_unresolved_reads`.

    A ``proto A R`` callee promises R values; they land on the caller's
    ``exit_stack`` top, position-preserving, so a ``None`` there means the
    builder could not name what the call returned. Downstream that is silent: a
    consumer sees a value that simply has no incoming edge, which reads as CLEAN
    to every may-analysis — the same shape ``frame_unresolved_reads`` exists to
    surface.

    WHY THIS EXISTS. It should have existed sooner. A recursive callee's result
    was ``None`` in 15 of the 231 distinct mainnet probes, and nothing noticed:
    the contracts lifted, the live-AVM dryrun matched outcome for outcome (the
    lost value did not steer control flow on the paths exercised), and the whole
    suite was green. It took a downstream prover failing to prove a true
    inductive invariant to show the value was gone. Only legacy (no ``proto``)
    callees are skipped, since they declare no result count to check against."""
    from ..structure import analyze_structure

    out: list = []
    for cs in analyze_structure(prog).call_sites:
        entry = cs.target_entry
        if entry is None:
            continue
        nret = _proto_nret(entry)
        if not nret:
            continue                       # legacy sub, or returns nothing
        call = next((a for a in reversed(cs.callsub_bb.assignments)
                     if a.op == "callsub"), None)
        if call is None:
            continue
        es = cs.callsub_bb.exit_stack
        for slot in range(1, nret + 1):
            if len(es) < slot or es[-slot] is None:
                out.append((call, slot))
    return out


def frame_value_sources(prog: SSAProgram) -> dict:
    """``frame_param_sources`` unioned with :func:`frame_local_sources` — every
    value a ``frame_dig`` may read, wherever it came from.

    What a MAY consumer wants: a frame read is a frame read, and splitting the
    map by whether the slot happens to hold a parameter or a written local only
    invites using the half that is in scope. MUST consumers must NOT use this —
    ``security._value_flow`` needs the param set specifically, since "every
    caller pins this arg" is a different claim from "every write to this slot
    flows".

    Warns ONCE per program about the reads it cannot source
    (:func:`frame_unresolved_reads`). Every MAY consumer routes through here, so
    this is the one place that sees the blind spot — and a value that reads clean
    because nothing could be resolved must not be indistinguishable from one that
    reads clean because it IS clean."""
    out = {k: set(v) for k, v in frame_param_sources(prog).items()}
    for k, v in frame_local_sources(prog).items():
        out.setdefault(k, set()).update(v)
    if not getattr(prog, "_frame_unresolved_warned", False):
        try:
            prog._frame_unresolved_warned = True
        except AttributeError:          # only if SSAProgram ever gains __slots__
            pass
        blind = frame_unresolved_reads(prog)
        if blind:
            where = ", ".join(f"{a.location.file}:{a.location.line}"
                             for a in blind[:5])
            logger.warning(
                "%d frame read(s) of a local could not be sourced, so they "
                "read as CLEAN and any value reaching them is invisible to the "
                "SSA taint layer (%s%s). Cause: no routine-relative depth after a "
                "callsub; see frame_unresolved_reads.",
                len(blind), where, " …" if len(blind) > 5 else "")
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
