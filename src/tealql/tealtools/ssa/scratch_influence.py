"""Scratch-slot reaching-definitions — per ``load N``, the stored-value keys that
MAY reach it, published as the ``scratch_stores`` graph annotation.

HAZARD: the relation is MAY, not must. Both consumer styles read it: taint takes
the union (may), const-prop requires every reaching key to agree (must). A change
that drops a reaching key is unsound for both — and note a scratch store with no
in-program ``load`` is NOT dead, since ``gload``/``gloads``/``gloadss`` read it
from other transactions in the group.
"""
from __future__ import annotations

from .models import Phi, SSAVar
from .program import SSAProgram

# Sentinel value-keys, shaped like real ``(file, line, index)`` keys so every
# consumer's unpack/lookup works; the ``<...>`` file can never collide with a real
# one, so ``prog.var(*key)`` returns None and must-consumers bail.
# UNINIT_STORE = the AVM's zero-initialised scratch (a load reachable from entry
# with no store on some path reads uint64 0, so const-prop may resolve it to
# ``int 0`` if every real store agrees); UNKNOWN_STORE = an unresolvable stored
# value (model underflow, leafless phi) or a dynamic ``stores``.
#
# HAZARD: UNKNOWN_STORE must stay an ELEMENT of the reaching set, never an empty
# set — an empty set vanishes at a CFG join (``set() | {k} == {k}``), erasing the
# "unknown value may reach here" fact and letting must-consumers see false
# agreement.
UNINIT_STORE = ("<scratch-uninit>", 0, 0)
UNKNOWN_STORE = ("<scratch-unknown>", 0, 0)


def _leaf_value_keys(v, seen=None) -> set:
    """The ``(file, line, index)`` keys of the SSAVar leaves of a stored value.

    HAZARD: a ``Phi`` has no key of its own, so a ``store`` of one must be
    flattened to its SSAVar arg leaves or the load sees no reaching def at all
    (losing scratch flow for the "merge, then spill to a slot" codegen). Sound
    both ways: the stored value IS one of the leaves, so MAY consumers (taint)
    take every leaf and MUST consumers (const-prop) require them all to agree."""
    if isinstance(v, SSAVar):
        return {(v.file, v.line, v.index)}
    if isinstance(v, Phi):
        if seen is None:
            seen = set()
        if id(v) in seen:
            return set()
        seen.add(id(v))
        out: set = set()
        for arg in v.args:
            out |= _leaf_value_keys(arg, seen)
        return out
    return set()


def compute_scratch_influence(prog: SSAProgram) -> dict:
    """Classical reaching-definitions over scratch slots:
    ``{(load_file, load_line): [(val_file, val_line, val_idx), …]}``, whose keys
    may include the :data:`UNINIT_STORE` / :data:`UNKNOWN_STORE` sentinels.

    HAZARD: a dynamic ``stores`` (slot popped off the stack) kills EVERY slot with
    an unknown value — it may write any of them. A dynamic ``loads`` reads an
    unknown slot and contributes nothing, so its output stays unresolvable.
    """
    # Per-BB walk collecting ``(op_index, kind, slot, val_keys)`` events in order;
    # kind is "store" (immediate), "storeany" (dynamic ``stores``) or "load".
    bb_events: dict = {}
    bb_loads: dict = {}  # bb -> list of (load_op, slot, op_index)
    for b in prog.blocks.values():
        events: list = []
        loads_here: list = []
        # Functional DCE may remove copy-propagated loads/pushes from
        # ``b.assignments``. Scratch semantics belongs to the canonical AVM
        # instruction stream and therefore survives that presentation cleanup.
        instructions = getattr(b, "stack_assignments", ()) or b.assignments
        for i, a in enumerate(instructions):
            if a.op == "stores":
                # Runtime target slot — may overwrite ANY slot with a value we
                # can't name, so record a universal kill; skipping it let a
                # must-consumer read ``store 0; …; stores; load 0`` as stale.
                events.append((i, "storeany", None, None))
                continue
            try:
                slot = int(a.immediates.strip().split()[0])
            except (ValueError, IndexError, AttributeError):
                continue
            if a.op == "store":
                # ALWAYS record the store so it KILLs the slot; an unresolvable
                # operand records the UNKNOWN sentinel, never an empty set — which
                # both kept a stale clobbered value alive and vanished at joins.
                keys = _leaf_value_keys(a.inputs[0]) if a.inputs else set()
                events.append((i, "store", slot, keys or {UNKNOWN_STORE}))
            elif a.op == "load":
                events.append((i, "load", slot, None))
                loads_here.append((a, slot, i))
        bb_events[b] = events
        bb_loads[b] = loads_here

    # The slot universe: every immediate slot mentioned anywhere. A slot only ever
    # accessed dynamically never appears in the influences map, so this suffices.
    universe: set = set()
    for events in bb_events.values():
        for _, kind, slot, _ in events:
            if slot is not None:
                universe.add(slot)

    # gen[B][slot] = the LAST store to slot in B; kill[B] = slots written in B. A
    # ``storeany`` kills the whole universe; a later store re-defines its own slot.
    gen: dict = {b: {} for b in prog.blocks.values()}
    kill: dict = {b: set() for b in prog.blocks.values()}
    for b, events in bb_events.items():
        for _, kind, slot, val_keys in events:
            if kind == "store":
                kill[b].add(slot)
                gen[b][slot] = set(val_keys)
            elif kind == "storeany":
                kill[b].update(universe)
                for s in universe:
                    gen[b][s] = {UNKNOWN_STORE}

    # Entry seeding: the AVM zero-initialises scratch, so every slot holds the
    # UNINIT pseudo-def at each program entry. Entry = the block holding the file's
    # FIRST instruction, NOT "blocks with no predecessors" — a program whose first
    # block is a branch target has none, so the pseudo-def would vanish and the
    # store-on-one-path / load-at-join flag idiom would fold to the stored constant.
    seed: dict = {b: {} for b in prog.blocks.values()}
    first_by_file: dict = {}
    for b in prog.blocks.values():
        cur = first_by_file.get(b.file)
        if cur is None or b.first_line < cur.first_line:
            first_by_file[b.file] = b
    for b in first_by_file.values():
        seed[b] = {slot: {UNINIT_STORE} for slot in universe}

    # Fixed point at BB granularity:
    #   in[B][slot]  = seed[B][slot] ∪ ⋃_{pred} out[pred][slot]
    #   out[B][slot] = in[B][slot] (if slot not killed) ∪ gen[B][slot]
    in_set: dict = {b: {} for b in prog.blocks.values()}
    out_set: dict = {b: {} for b in prog.blocks.values()}
    changed = True
    while changed:
        changed = False
        for b in prog.blocks.values():
            new_in: dict = {slot: set(srcs) for slot, srcs in seed[b].items()}
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
            for slot, val_keys in gen[b].items():
                new_out[slot] = set(val_keys)
            if new_in != in_set[b] or new_out != out_set[b]:
                changed = True
                in_set[b] = new_in
                out_set[b] = new_out

    # Per-BB op-walk: for each ``load N``, the reaching set at the load's program
    # point — the in-set updated by any earlier same-slot store in this BB.
    influences: dict = {}
    for b in prog.blocks.values():
        local = {
            slot: set(srcs) for slot, srcs in in_set[b].items()
        }
        for ev_i, kind, slot, val_keys in bb_events[b]:
            if kind == "store":
                local[slot] = set(val_keys)
            elif kind == "storeany":
                for s in universe:
                    local[s] = {UNKNOWN_STORE}
            elif kind == "load":
                srcs = local.get(slot)
                if srcs:
                    instructions = getattr(b, "stack_assignments", ()) or b.assignments
                    load_op = instructions[ev_i]
                    key = (load_op.location.file, load_op.location.line)
                    influences.setdefault(key, set()).update(srcs)

    return {k: list(v) for k, v in influences.items()}
