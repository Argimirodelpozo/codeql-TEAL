"""Routine execution records and their conservative physical-SSA projection.

Ownership is a layout partition. Execution can cross that partition through a
shared tail. Each routine keeps its own return stacks; public opcode operands
join the values observed in every context, preserving source-position identity.
"""
from types import SimpleNamespace


def execution_bodies(blocks, partition, successors, *, max_visits=100_000):
    owned = {}
    for block in blocks:
        owned.setdefault(partition.get(block), []).append(block)
    result = {}
    visits = 0
    for entry in owned:
        if entry is None:
            continue
        seen, work = set(), [entry]
        while work:
            block = work.pop()
            if block in seen:
                continue
            seen.add(block)
            visits += 1
            if visits > max_visits:
                return owned, False
            work.extend(successors(block))
        result[entry] = sorted(seen, key=lambda b: b.key)
    if None in owned:
        result[None] = owned[None]
    return result, True


def snapshot(result, body, poisoned):
    """Retain unprojected operands and exits for future calls to this routine."""
    return SimpleNamespace(
        args={id(op): result.args.get(id(op), []) for b in body for op in b.ops},
        exit={b: result.exit[b] for b in body if b in result.exit},
        frame_skewed=set(result.frame_skewed),
        poisoned=poisoned,
    )


def publish(target, local, body, seen, phi_factory):
    """Join complete context operands, without selecting one owner's values."""
    def merge(block, slot, left, right):
        if left is right:
            return left
        if left is None or right is None:
            return None                 # an unnamed context must stay visible
        phi = phi_factory(block, slot)
        phi.args.extend((left, right))
        target.phis.setdefault(block, []).append((slot, phi))
        return phi

    for block in body:
        for op in block.ops:
            values = local.args.get(id(op), [])
            if block in seen:
                old = target.args.get(id(op), [])
                values = [merge(block, i + 1,
                                old[i] if i < len(old) else None,
                                values[i] if i < len(values) else None)
                          for i in range(max(len(old), len(values)))]
            target.args[id(op)] = values
        stack = local.exit.get(block, [])
        if block in seen:
            old = target.exit.get(block, [])
            stack = [merge(block, slot,
                           old[-slot] if slot <= len(old) else None,
                           stack[-slot] if slot <= len(stack) else None)
                     for slot in range(max(len(old), len(stack)), 0, -1)]
        target.exit[block] = stack
    for block, phis in local.phis.items():
        target.phis.setdefault(block, []).extend(phis)
    target.unresolved.update(local.unresolved)
    target.frame_skewed.update(local.frame_skewed)
