"""Scratch-slot reaching-definitions for SSA programs.

Per ``load N`` opcode, the set of stored-value SSAVar keys that may
reach it via the CFG (classical reaching-definitions over scratch
slots). Replaces the ``scratchInfluence.ql`` query; the result is
exposed through the ``scratch_stores`` graph annotation consumed by the
detectors (:func:`tealtools.detections.common._scratch_stores_for`),
the taint engine, and the ``SSAProgram`` scratch-bridge passes.

Kept as a separate module so the ssa.py substrate stays focused on SSA
construction; this is TEAL-semantics analysis layered on top of those
types (see the const_fold / input_prop / inner_txn_fields passes).
"""
from __future__ import annotations

from ..ssa import SSAProgram, SSAVar


def compute_scratch_influence(prog: SSAProgram) -> dict:
    """Per ``load N`` opcode, the set of stored-value SSAVar keys that
    may reach it via the CFG. Classical reaching-definitions analysis
    over scratch slots:

      - ``store N``  → gen[B][N] = {value-key}, kill[B] ⊇ {N}
      - ``load  N``  reads at this program point the union of ``store N``
                     value-keys reaching here (in-set ∪ any earlier
                     store in the same BB, with later same-slot stores
                     in the BB killing earlier ones).

    Returns ``{(load_file, load_line): [(val_file, val_line, val_idx), …]}``.
    Replaces the ``scratchInfluence.ql`` query so we can drop that
    from the load path.

    Only handles the immediate forms (``store N`` / ``load N``); the
    dynamic forms (``stores`` / ``loads``) pop the slot off the stack
    and aren't covered, mirroring the QL query.
    """
    # Per-BB walk to collect store/load events in order. Each event
    # is a tuple ``(kind, slot, val_key_or_None)``; ``kind`` is
    # ``"store"`` or ``"load"``. Value keys are
    # ``(file, line, index)`` matching the QL emission shape.
    bb_events: dict = {}
    bb_loads: dict = {}  # bb -> list of (load_op, slot, op_index)
    for b in prog.blocks.values():
        events: list = []
        loads_here: list = []
        for i, a in enumerate(b.assignments):
            try:
                slot = int(a.immediates.strip().split()[0])
            except (ValueError, IndexError, AttributeError):
                continue
            if a.op == "store":
                if a.inputs:
                    v = a.inputs[0]
                    if isinstance(v, SSAVar):
                        events.append((
                            i, "store", slot, (v.file, v.line, v.index)
                        ))
            elif a.op == "load":
                events.append((i, "load", slot, None))
                loads_here.append((a, slot, i))
        bb_events[b] = events
        bb_loads[b] = loads_here

    # gen[B][slot] = set with the LAST store-slot's value-key in B.
    # kill[B] = set of slots written in B.
    gen: dict = {b: {} for b in prog.blocks.values()}
    kill: dict = {b: set() for b in prog.blocks.values()}
    for b, events in bb_events.items():
        for _, kind, slot, val_key in events:
            if kind == "store":
                gen[b][slot] = val_key
                kill[b].add(slot)

    # Fixed-point reaching-definitions at BB granularity.
    # in[B][slot] = ⋃_{pred} out[pred][slot]
    # out[B][slot] = in[B][slot] (if slot not killed) ∪ gen[B][slot]
    in_set: dict = {b: {} for b in prog.blocks.values()}
    out_set: dict = {b: {} for b in prog.blocks.values()}
    changed = True
    while changed:
        changed = False
        for b in prog.blocks.values():
            new_in: dict = {}
            for pred in b.predecessors:
                for slot, srcs in out_set[pred].items():
                    if slot in new_in:
                        new_in[slot].update(srcs)
                    else:
                        new_in[slot] = set(srcs)
            new_out: dict = {}
            for slot, srcs in new_in.items():
                if slot not in kill[b]:
                    new_out[slot] = set(srcs)
            for slot, val_key in gen[b].items():
                new_out[slot] = {val_key}
            if new_in != in_set[b] or new_out != out_set[b]:
                changed = True
                in_set[b] = new_in
                out_set[b] = new_out

    # Per-BB op-walk: for each ``load N``, gather the reaching set at
    # the load's program point (in-set merged with any earlier
    # same-slot store in this BB; later same-slot stores kill).
    influences: dict = {}
    for b in prog.blocks.values():
        local = {
            slot: set(srcs) for slot, srcs in in_set[b].items()
        }
        for ev_i, kind, slot, val_key in bb_events[b]:
            if kind == "store":
                local[slot] = {val_key}
            elif kind == "load":
                srcs = local.get(slot)
                if srcs:
                    load_op = b.assignments[ev_i]
                    key = (load_op.location.file, load_op.location.line)
                    influences.setdefault(key, set()).update(srcs)

    return {k: list(v) for k, v in influences.items()}
