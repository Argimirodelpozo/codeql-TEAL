"""Sound MAY-influence over AVM scratch slots.

The product deliberately separates values a load may return from dynamic slot
selectors that influence *which* value it returns. Const propagation consumes
only values; taint consumes both. Zero-initialisation and unresolved values stay
explicit so neither interpretation can turn uncertainty into an empty set.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Const, Phi, SSAVar
from .program import SSAProgram


# Backward-compatible value keys used by graph annotations and MUST consumers.
UNINIT_STORE = ("<scratch-uninit>", 0, 0)
UNKNOWN_STORE = ("<scratch-unknown>", 0, 0)

# Abstract slot holding values written through a completely unknown dynamic
# index to otherwise-unmentioned slots. A later dynamic load must include it;
# a static load does not read it (the dynamic write is also added to every
# statically-mentioned slot separately).
_OTHER_SLOT = -1


@dataclass(frozen=True)
class ScratchInfluence:
    """Influence fact for one ``load``/``loads`` result.

    ``values`` are real SSA leaves that may be returned. ``selectors`` are
    dynamic slot operands whose choice may change the returned value.
    ``zero_initialized`` records the AVM's implicit uint64 zero and ``unknown``
    records a value the SSA could not name.
    """

    values: frozenset[tuple[str, int, int]] = frozenset()
    selectors: frozenset[tuple[str, int, int]] = frozenset()
    zero_initialized: bool = False
    unknown: bool = False

    @classmethod
    def from_sets(cls, values: set, selectors: set) -> "ScratchInfluence":
        return cls(
            values=frozenset(values - {UNINIT_STORE, UNKNOWN_STORE}),
            selectors=frozenset(selectors),
            zero_initialized=UNINIT_STORE in values,
            unknown=UNKNOWN_STORE in values,
        )

    def legacy_value_keys(self) -> tuple[tuple[str, int, int], ...]:
        """Old ``scratch_stores`` shape, for const/MUST compatibility."""
        out = set(self.values)
        if self.zero_initialized:
            out.add(UNINIT_STORE)
        if self.unknown:
            out.add(UNKNOWN_STORE)
        return tuple(sorted(out, key=repr))

    @property
    def taint_keys(self) -> frozenset[tuple[str, int, int]]:
        """Every named SSA dependency relevant to a MAY taint consumer."""
        return self.values | self.selectors


def _leaf_value_keys(v, seen=None) -> set:
    """Transitive public-SSA leaf keys of ``v`` (cycle-safe for phis)."""
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


def _slot_domain(value) -> frozenset[int] | None:
    """Known feasible scratch slots, or ``None`` for any of 0..255.

    Constants and installed ranges narrow dynamic-index opcodes without a
    separate syntax special case. An out-of-range-only domain represents a
    panicking instruction and contributes no continuing execution.
    """
    cv = value if isinstance(value, Const) else getattr(value, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "int":
        try:
            n = int(cv.value, 0)
        except (TypeError, ValueError):
            pass
        else:
            return frozenset({n}) if 0 <= n <= 255 else frozenset()
    r = getattr(value, "range", None)
    if r is not None:
        lo, hi = max(0, r.lo), min(255, r.hi)
        if lo > hi:
            return frozenset()
        return frozenset(range(lo, hi + 1))
    return None


def _copy_state(state: dict) -> dict:
    return {slot: set(srcs) for slot, srcs in state.items()}


def _join_into(dst: dict, src: dict) -> None:
    for slot, values in src.items():
        dst.setdefault(slot, set()).update(values)


def _targets(domain: frozenset[int] | None, universe: set[int]) -> set[int]:
    return set(universe) | {_OTHER_SLOT} if domain is None else set(domain)


def _transfer(events: list, values: dict, controls: dict, universe: set[int]) -> None:
    """Execute one block's scratch effects over copied input states."""
    for _i, kind, domain, val_keys, selector_keys in events:
        if kind != "store":
            continue
        targets = _targets(domain, universe)
        exact = domain is not None and len(domain) == 1
        for slot in targets:
            if exact:
                values[slot] = set(val_keys)
                controls[slot] = set()
            else:
                # A dynamic write MAY hit this slot and MAY miss it: retain the
                # old reaching values and add the stored value. Its selector is
                # a control dependency because it decides whether the overwrite
                # happens.
                values.setdefault(slot, set()).update(val_keys)
                controls.setdefault(slot, set()).update(selector_keys)


def compute_scratch_facts(prog: SSAProgram) -> dict[tuple[str, int], ScratchInfluence]:
    """Compute typed MAY facts for immediate and dynamic scratch reads."""
    bb_events: dict = {}
    universe: set[int] = set()

    for block in prog.blocks.values():
        events: list = []
        instructions = getattr(block, "stack_assignments", ()) or block.assignments
        for i, assignment in enumerate(instructions):
            op = assignment.op
            if op == "store":
                try:
                    slot = int(assignment.immediates.strip().split()[0])
                except (ValueError, IndexError, AttributeError):
                    continue
                domain = frozenset({slot}) if 0 <= slot <= 255 else frozenset()
                value = assignment.inputs[0] if assignment.inputs else None
                val_keys = _leaf_value_keys(value) or {UNKNOWN_STORE}
                events.append((i, "store", domain, val_keys, set()))
                universe.update(domain)
            elif op == "stores":
                slot_value = assignment.inputs[0] if assignment.inputs else None
                stored_value = assignment.inputs[1] if len(assignment.inputs) > 1 else None
                domain = _slot_domain(slot_value)
                val_keys = _leaf_value_keys(stored_value) or {UNKNOWN_STORE}
                selector_keys = (set() if domain is not None and len(domain) <= 1
                                 else _leaf_value_keys(slot_value))
                events.append((i, "store", domain, val_keys, selector_keys))
                if domain is not None:
                    universe.update(domain)
            elif op == "load":
                try:
                    slot = int(assignment.immediates.strip().split()[0])
                except (ValueError, IndexError, AttributeError):
                    continue
                domain = frozenset({slot}) if 0 <= slot <= 255 else frozenset()
                events.append((i, "load", domain, None, set()))
                universe.update(domain)
            elif op == "loads":
                slot_value = assignment.inputs[0] if assignment.inputs else None
                domain = _slot_domain(slot_value)
                selector_keys = (set() if domain is not None and len(domain) <= 1
                                 else _leaf_value_keys(slot_value))
                events.append((i, "load", domain, None, selector_keys))
                if domain is not None:
                    universe.update(domain)
        bb_events[block] = events

    tracked_slots = set(universe) | {_OTHER_SLOT}
    first_by_file = {b.file: b for b in prog.entry_blocks()}
    seed_values = {
        block: ({slot: {UNINIT_STORE} for slot in tracked_slots}
                if first_by_file.get(block.file) is block else {})
        for block in prog.blocks.values()
    }

    in_values = {b: {} for b in prog.blocks.values()}
    out_values = {b: {} for b in prog.blocks.values()}
    in_controls = {b: {} for b in prog.blocks.values()}
    out_controls = {b: {} for b in prog.blocks.values()}

    changed = True
    while changed:
        changed = False
        for block in prog.blocks.values():
            new_values = _copy_state(seed_values[block])
            new_controls: dict = {}
            for pred in block.predecessors:
                _join_into(new_values, out_values[pred])
                _join_into(new_controls, out_controls[pred])
            next_values, next_controls = _copy_state(new_values), _copy_state(new_controls)
            _transfer(bb_events[block], next_values, next_controls, universe)
            if (new_values != in_values[block] or new_controls != in_controls[block]
                    or next_values != out_values[block]
                    or next_controls != out_controls[block]):
                changed = True
                in_values[block], in_controls[block] = new_values, new_controls
                out_values[block], out_controls[block] = next_values, next_controls

    facts: dict[tuple[str, int], ScratchInfluence] = {}
    for block in prog.blocks.values():
        values = _copy_state(in_values[block])
        controls = _copy_state(in_controls[block])
        instructions = getattr(block, "stack_assignments", ()) or block.assignments
        for i, kind, domain, val_keys, selector_keys in bb_events[block]:
            if kind == "store":
                _transfer([(i, kind, domain, val_keys, selector_keys)],
                          values, controls, universe)
                continue
            targets = _targets(domain, universe)
            reaching_values: set = set()
            reaching_controls: set = set(selector_keys)
            for slot in targets:
                reaching_values.update(values.get(slot, ()))
                reaching_controls.update(controls.get(slot, ()))
            if not reaching_values:
                continue
            load = instructions[i]
            key = (load.location.file, load.location.line)
            fact = ScratchInfluence.from_sets(reaching_values, reaching_controls)
            previous = facts.get(key)
            if previous is not None:
                fact = ScratchInfluence(
                    values=previous.values | fact.values,
                    selectors=previous.selectors | fact.selectors,
                    zero_initialized=previous.zero_initialized or fact.zero_initialized,
                    unknown=previous.unknown or fact.unknown,
                )
            facts[key] = fact
    return facts


def compute_scratch_influence(prog: SSAProgram) -> dict:
    """Backward-compatible ``location -> legacy value keys`` projection."""
    return {location: list(fact.legacy_value_keys())
            for location, fact in compute_scratch_facts(prog).items()}


__all__ = [
    "ScratchInfluence",
    "UNINIT_STORE",
    "UNKNOWN_STORE",
    "compute_scratch_facts",
    "compute_scratch_influence",
]
