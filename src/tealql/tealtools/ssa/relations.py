"""Compatibility frame-flow API plus non-frame implicit-flow diagnostics.

Frame-slot classification and value provenance now live beside the canonical
stack interpreter in :mod:`tealql.tealtools.ssa.frame_slots`. Established names
remain here so downstream consumers do not need a lockstep migration.
"""
from __future__ import annotations

from typing import Optional

from ..ssa import SSAProgram
from ..ssa.frame_slots import (
    gap_sources as frame_gap_sources,
    local_sources as frame_local_sources,
    logger,
    parameter_sources as frame_param_sources,
    unresolved_reads as frame_unresolved_reads,
    value_sources as frame_value_sources,
)


def _proto_nret(entry_bb) -> "Optional[int]":
    for assignment in entry_bb.assignments:
        if assignment.op == "proto":
            tokens = (assignment.immediates or "").split()
            try:
                return int(tokens[1]) if len(tokens) > 1 else 0
            except ValueError:
                return 0
    return None


def unresolved_call_results(prog: SSAProgram) -> list:
    """Declared call results the canonical SSA could not produce.

    These are call-boundary dataflow gaps: a ``proto A R`` promises each slot,
    but an absent/``None`` caller exit value would otherwise look clean to a
    MAY analysis. Legacy routines are skipped because they declare no count.
    """
    from ..cfg.structure import analyze_structure
    from ..cfg.subroutines import is_retsub_block

    out: list = []
    structure = analyze_structure(prog)
    bodies = {sub.entry_bb: sub.body for sub in structure.subroutines}
    for call_site in structure.call_sites:
        entry = call_site.target_entry
        if entry is None:
            continue
        body = bodies.get(entry)
        if (call_site.continuation_bb is None and body
                and not any(is_retsub_block(block) for block in body)):
            # `proto A R` constrains a retsub, not a whole-program return.
            # A callee that only halts has no result consumed by its caller.
            continue
        nret = _proto_nret(entry)
        if not nret:
            continue
        call = next((assignment for assignment in reversed(
            call_site.callsub_bb.assignments) if assignment.op == "callsub"), None)
        if call is None:
            continue
        exit_stack = call_site.callsub_bb.exit_stack
        for slot in range(1, nret + 1):
            if len(exit_stack) < slot or exit_stack[-slot] is None:
                out.append((call, slot))
    return out


def shared_execution_blocks(prog: SSAProgram) -> dict:
    """Blocks executed in more than one routine ownership context.

    This is a physical overlap census, not a count of missing values. The stack
    interpreter records each routine separately and joins its public operands.
    :func:`unresolved_shared_execution_blocks` identifies incomplete records.
    """
    from ..cfg.subroutines import pyblock_partition, _pyblock_return_point
    from ..ssa import stacksim

    py = getattr(prog, "_pyssa", None)
    if py is None:
        return {}
    partition = pyblock_partition(py.blocks)
    return_points = _pyblock_return_point(py.blocks)
    every = set(py.blocks)
    hits: dict = {}
    for entry in (block for block in py.blocks if partition.get(block) is block):
        seen, work = {entry}, [entry]
        while work:
            block = work.pop()
            for successor in stacksim._isucc(
                    block, every, return_points, owned_only=False):
                if successor not in seen:
                    seen.add(successor)
                    work.append(successor)
        for block in seen:
            hits.setdefault(block, []).append(entry)
    return {block: entries for block, entries in hits.items()
            if len(entries) > 1}


def unresolved_shared_execution_blocks(prog: SSAProgram) -> dict:
    """Shared blocks missing an execution context or one of its operands."""
    shared = shared_execution_blocks(prog)
    result = getattr(getattr(prog, '_pyssa', None), '_stack_result', None)
    if result is None or not result.contexts_complete:
        return shared
    missing = {}
    for block, entries in shared.items():
        for entry in entries:
            context = result.contexts.get(entry)
            if context is None or block not in context.exit:
                missing[block] = entries
                break
            for op in block.ops:
                needed = 1 if op.op in {'frame_dig', 'frame_bury'} else op.n_in
                args = context.args.get(id(op), ())
                if len(args) < needed or any(v is None for v in args):
                    missing[block] = entries
                    break
    return missing


def scratch_load_sources(prog: SSAProgram) -> dict:
    """Named MAY dependencies for each ``load``/``loads`` result.

    Includes both stored values and dynamic slot selectors. Unknown values have
    no SSAVar identity and are surfaced separately by
    :func:`scratch_unknown_loads` rather than silently disappearing.
    """
    prog._ensure_scratch_influence()
    out: dict = {}
    for (file, line), fact in (getattr(prog, "_scratch_facts", {}) or {}).items():
        load_var = prog.var(file, line, 1)
        if load_var is None:
            continue
        sources = [value for sf, sl, index in fact.taint_keys
                   if (value := prog.var(sf, sl, index)) is not None]
        if sources:
            out.setdefault(load_var, []).extend(sources)
    return out


def scratch_unknown_loads(prog: SSAProgram) -> set:
    """Scratch result vars whose MAY value contains an unnamed unknown."""
    prog._ensure_scratch_influence()
    return {
        value
        for (file, line), fact in (getattr(prog, "_scratch_facts", {}) or {}).items()
        if fact.unknown and (value := prog.var(file, line, 1)) is not None
    }


__all__ = [
    "frame_gap_sources",
    "frame_local_sources",
    "frame_param_sources",
    "frame_unresolved_reads",
    "frame_value_sources",
    "logger",
    "scratch_load_sources",
    "scratch_unknown_loads",
    "shared_execution_blocks",
    "unresolved_shared_execution_blocks",
    "unresolved_call_results",
]
