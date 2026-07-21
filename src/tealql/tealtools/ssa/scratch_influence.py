"""Scratch-slot reaching-definitions for SSA programs.

Per ``load N`` opcode, the set of stored-value SSAVar keys that may
reach it via the CFG (classical reaching-definitions over scratch
slots). The result is exposed through the ``scratch_stores`` graph
annotation consumed by the
detectors (:func:`tealql.security.common._scratch_stores_for`),
the taint engine, and the ``SSAProgram`` scratch-bridge passes.

A construction-time substrate helper: it lives in the ``ssa`` package
but is split out of ``ssa.py`` (which calls it eagerly while building a
program) so the builder stays focused on SSA construction. It is *not*
an optional ``passes/`` analysis — those layer on a finished program;
this one runs as part of producing it (cf. the sibling
:mod:`const_fold` / :mod:`inner_txn_fields` helpers).
"""
from __future__ import annotations

from .models import Phi, SSAVar
from .program import SSAProgram

# Sentinel value-keys. Both are 3-tuples shaped like real ``(file, line, index)``
# keys so every consumer's unpack/lookup works; the ``<...>`` file component can
# never collide with a real source file, so ``prog.var(*key)`` returns None and
# must-consumers bail (value-identity forwarding can't cross them).
#
# UNINIT_STORE — the AVM zero-initialises scratch, so a load reachable from
# program entry with NO store on some path reads uint64 0. That value is
# precisely known: const-prop consumers may resolve this key to ``int 0``
# (and must then require agreement with every real store, as always).
#
# UNKNOWN_STORE — a store whose value is unresolvable (model underflow,
# leafless phi) or a dynamic ``stores`` (any slot, any value). Nothing can be
# assumed; consumers must treat the load as unresolvable. Kept as an element of
# the reaching set — NOT an empty set — because an empty set vanishes at a CFG
# join (``set() | {k} == {k}``), which silently erased the "unknown value may
# reach here" fact and let must-consumers see false agreement.
UNINIT_STORE = ("<scratch-uninit>", 0, 0)
UNKNOWN_STORE = ("<scratch-unknown>", 0, 0)


def _leaf_value_keys(v, seen=None) -> set:
    """The ``(file, line, index)`` keys of the SSAVar leaves of a stored value.

    A plain ``SSAVar`` is its own leaf. A ``Phi`` has no ``(file, line, index)``
    key of its own and is not an ``SSAVar``, so a ``store`` of a phi value used to
    be dropped entirely (the load saw no reaching def) — a real reaching-def gap
    that silently lost scratch flow for the common "merge two values, spill to a
    slot" codegen pattern. We flatten the phi to its SSAVar arg leaves instead:
    the stored value IS one of those args, so for MAY consumers (taint) every leaf
    may reach the load, and for MUST consumers (const-prop) the leaves must all
    agree — both correct."""
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
    """Per ``load N`` opcode, the set of stored-value SSAVar keys that
    may reach it via the CFG. Classical reaching-definitions analysis
    over scratch slots:

      - ``store N``  → gen[B][N] = {value-key}, kill[B] ⊇ {N}
      - ``load  N``  reads at this program point the union of ``store N``
                     value-keys reaching here (in-set ∪ any earlier
                     store in the same BB, with later same-slot stores
                     in the BB killing earlier ones).

    Returns ``{(load_file, load_line): [(val_file, val_line, val_idx), …]}``,
    where the value keys may include the :data:`UNINIT_STORE` /
    :data:`UNKNOWN_STORE` sentinels (see the module header).

    Dynamic ``stores`` (slot popped off the stack) kills EVERY slot with an
    unknown value — it may write any of them. Dynamic ``loads`` reads an
    unknown slot and contributes nothing (its output stays unresolvable).
    """
    # Per-BB walk to collect store/load events in order. Each event
    # is a tuple ``(kind, slot, val_key_or_None)``; ``kind`` is
    # ``"store"`` (immediate), ``"storeany"`` (dynamic ``stores``) or
    # ``"load"``. Value keys are ``(file, line, index)``.
    bb_events: dict = {}
    bb_loads: dict = {}  # bb -> list of (load_op, slot, op_index)
    for b in prog.blocks.values():
        events: list = []
        loads_here: list = []
        for i, a in enumerate(b.assignments):
            if a.op == "stores":
                # Dynamic store: the target slot is a runtime value — it may
                # overwrite ANY slot with a value we can't name. Recorded as a
                # universal kill; skipping it (the old behaviour) let a
                # must-consumer resolve ``store 0; …; stores; load 0`` to the
                # stale constant.
                events.append((i, "storeany", None, None))
                continue
            try:
                slot = int(a.immediates.strip().split()[0])
            except (ValueError, IndexError, AttributeError):
                continue
            if a.op == "store":
                # ALWAYS record the store (so it KILLs the slot); an
                # unresolvable operand (model underflow / leafless phi) records
                # the UNKNOWN sentinel rather than an empty set — the empty set
                # both let a MUST consumer read a STALE reaching value the
                # store clobbered at runtime AND vanished at CFG joins.
                keys = _leaf_value_keys(a.inputs[0]) if a.inputs else set()
                events.append((i, "store", slot, keys or {UNKNOWN_STORE}))
            elif a.op == "load":
                events.append((i, "load", slot, None))
                loads_here.append((a, slot, i))
        bb_events[b] = events
        bb_loads[b] = loads_here

    # The slot universe: every immediate slot mentioned anywhere. (A slot only
    # ever accessed dynamically never appears in the influences map — same as
    # before — so the universe is sufficient for every reported load.)
    universe: set = set()
    for events in bb_events.values():
        for _, kind, slot, _ in events:
            if slot is not None:
                universe.add(slot)

    # gen[B][slot] = set with the LAST store-slot's value-key in B.
    # kill[B] = set of slots written in B. A ``storeany`` kills the whole
    # universe with UNKNOWN; a later immediate store re-defines its own slot.
    gen: dict = {b: {} for b in prog.blocks.values()}
    kill: dict = {b: set() for b in prog.blocks.values()}
    for b, events in bb_events.items():
        for _, kind, slot, val_keys in events:
            if kind == "store":
                kill[b].add(slot)                 # a store always overwrites the slot
                gen[b][slot] = set(val_keys)
            elif kind == "storeany":
                kill[b].update(universe)
                for s in universe:
                    gen[b][s] = {UNKNOWN_STORE}

    # Entry seeding: the AVM zero-initialises scratch, so at each program entry
    # every slot holds the UNINIT pseudo-definition. The entry is the block
    # holding the file's FIRST instruction — NOT "blocks with no predecessors"
    # (a program whose first block is a branch target has none, and the
    # pseudo-def would silently vanish, letting a must-consumer fold the
    # store-on-one-path / load-at-join flag idiom to the stored constant).
    seed: dict = {b: {} for b in prog.blocks.values()}
    first_by_file: dict = {}
    for b in prog.blocks.values():
        cur = first_by_file.get(b.file)
        if cur is None or b.first_line < cur.first_line:
            first_by_file[b.file] = b
    for b in first_by_file.values():
        seed[b] = {slot: {UNINIT_STORE} for slot in universe}

    # Fixed-point reaching-definitions at BB granularity.
    # in[B][slot] = seed[B][slot] ∪ ⋃_{pred} out[pred][slot]
    # out[B][slot] = in[B][slot] (if slot not killed) ∪ gen[B][slot]
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

    # Per-BB op-walk: for each ``load N``, gather the reaching set at
    # the load's program point (in-set merged with any earlier
    # same-slot store in this BB; later same-slot stores kill).
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
                    load_op = b.assignments[ev_i]
                    key = (load_op.location.file, load_op.location.line)
                    influences.setdefault(key, set()).update(srcs)

    return {k: list(v) for k, v in influences.items()}
