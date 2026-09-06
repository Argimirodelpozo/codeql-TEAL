"""Preserve legacy return-depth alternatives through an immediate flag guard.

The physical stack for each return is retained until the caller consumes its
flag. Only literal flags and the frontend's canonical edge polarity eliminate
alternatives; unknown flags stay in both outcomes. Other predecessors, loops
into the guard, intervening instructions and exhausted bounds refuse refinement.
"""
from __future__ import annotations


class ReturnShapes:
    def __init__(self, blocks, edge_polarity):
        self.variants = {}
        self.edges = {}
        self.polarity = edge_polarity or {}
        self.constants = {}
        for block in blocks:
            for op in block.ops:
                source = getattr(op, 'source_assignment', None)
                for output, original in zip(op.outputs, getattr(source, 'outputs', ())):
                    const = original.const_value
                    if const is None or const.kind != 'int':
                        continue
                    try:
                        number = int(const.value)
                    except (ValueError, TypeError):
                        continue
                    if 0 <= number < 2 ** 64:
                        self.constants[output] = number

    def fork(self):
        result = ReturnShapes((), self.polarity)
        result.constants = self.constants
        return result

    def capture(self, continuation, base, exits):
        if (not continuation.ops or continuation.ops[0].op not in {'assert', 'bz', 'bnz'}
                or not exits or len(exits) > 32
                or sum(len(base) + len(st) for st in exits) > 4096):
            return
        self.variants[continuation] = [list(base) + list(st) for st in exits]

    def after_guard(self, block, op, merge):
        variants = self.variants.pop(block, None)
        if variants is None:
            return None

        def selected(nonzero):
            kept = []
            for stack in variants:
                if not stack:
                    continue             # consuming the flag underflows
                flag = self.constants.get(stack[-1])
                if flag is None or bool(flag) == nonzero:
                    kept.append(stack[:-1])
            # No alternatives is infeasible, not evidence for a value. Leave
            # the ordinary simulation in place on such an edge.
            return merge(kept) if kept else None

        if op.op == 'assert':
            return selected(True)
        if op.op in {'bz', 'bnz'} and len(block.ops) == 1:
            for target in block.succs:
                labels = self.polarity.get((block.key, target.key))
                if labels not in (frozenset({'true'}), frozenset({'false'})):
                    continue             # collapsed arms do not filter a flag
                stack = selected(labels == frozenset({'true'}))
                if stack is not None:
                    self.edges[block, target] = stack
        return None
