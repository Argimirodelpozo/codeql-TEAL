"""Bounded interval fixed points for cyclic SSA value webs.

Threshold widening guarantees fast convergence; simultaneous narrowing retains
the post-fixpoint property. Partial iterates, partial phis and unseeded cycles
never become numeric claims. This domain proves values, not termination.
"""
from ..ssa import Phi, IntRange
from ._range_arithmetic import _arith_result_range, _unary_result_range, _clamp_uint64
from .intervals import TOP

BOTTOM = object()
_BINARY = {'+', '-', '*', '/', '%', '&', '|', '^', 'shl', 'shr'}
_UNARY = {'~', 'sqrt'}


def _join(values):
    values = [v for v in values if v is not BOTTOM]
    if not values:
        return BOTTOM
    if any(v is None for v in values):
        return None
    return IntRange(min(v.lo for v in values), max(v.hi for v in values))


def _contains(outer, inner):
    return (inner is BOTTOM or outer is None or outer == inner
            or outer is not BOTTOM and inner is not None
            and outer.lo <= inner.lo <= inner.hi <= outer.hi)


class LoopInvariants:
    def __init__(self, base_query, *, max_nodes=128, max_steps=4096):
        self.base = base_query
        self.facts = base_query.facts
        self.max_nodes, self.max_steps = max_nodes, max_steps
        self.cache = {}
        self.reason = ''

    def query(self, value):
        value = self.facts.resolve(value)
        if value in self.cache:
            return self.cache[value]
        result = self._solve(value)
        self.cache[value] = result
        return result

    def _solve(self, root):
        self.reason = ''
        work, nodes, dependencies = [root], [], {}
        thresholds = {0, TOP.hi}
        while work:
            value = self.facts.resolve(work.pop())
            if value in dependencies:
                continue
            if len(nodes) >= self.max_nodes:
                self.reason = 'invariant dependency budget exhausted'
                return None
            nodes.append(value)
            source = getattr(value, 'defined_by', None)
            if isinstance(value, Phi) and not value.partial:
                args = value.args
            elif (source is not None and len(source.outputs) == 1
                  and (source.op in _BINARY and len(source.inputs) == 2
                       or source.op in _UNARY and len(source.inputs) == 1)):
                args = source.inputs
            else:
                args = ()
            dependencies[value] = tuple(self.facts.resolve(v) for v in args)
            work.extend(args)
            bounds = self.base._bounds(value)
            if bounds is not None:
                thresholds.update((bounds.lo, bounds.hi))
            if source is not None:
                for predicate in self.base.predicates.predicates_at(source.location.file, source.location.line):
                    for other in (predicate.value, *predicate.args):
                        bounds = self.base._bounds(other)
                        if bounds is not None:
                            thresholds.update((bounds.lo, bounds.hi))
        thresholds = sorted(n for n in thresholds if 0 <= n <= TOP.hi)
        state = dict.fromkeys(nodes, BOTTOM)
        remaining = self.max_steps

        def transfer(value, env):
            args = dependencies[value]
            if isinstance(value, Phi):
                return None if value.partial else _join(env[v] for v in args)
            source = getattr(value, 'defined_by', None)
            if not args:
                return self.base._bounds(value)
            operands = []
            for arg in args:
                bounds = env[arg]
                if bounds is BOTTOM:
                    return BOTTOM
                refined, reachable = self.base._refine(
                    arg, bounds, source.location.file, source.location.line)
                if not reachable:
                    return BOTTOM
                operands.append(refined or TOP)
            raw = (_arith_result_range(source.op, operands[1], operands[0])
                   if len(operands) == 2 else _unary_result_range(source.op, operands[0]))
            if raw is None:
                return BOTTOM
            lo, hi = _clamp_uint64(*raw)
            return IntRange(lo, hi) if lo <= hi else BOTTOM

        def sweep(env):
            nonlocal remaining
            remaining -= len(nodes)
            if remaining < 0:
                return None
            return {v: transfer(v, env) for v in nodes}

        while True:
            proposed = sweep(state)
            if proposed is None:
                self.reason = 'invariant work budget exhausted'
                return None
            if all(_contains(state[v], proposed[v]) for v in nodes):
                break
            updated = {}
            for value in nodes:
                old, new = state[value], _join((state[value], proposed[value]))
                if isinstance(old, IntRange) and isinstance(new, IntRange):
                    lo = max(t for t in thresholds if t <= new.lo) if new.lo < old.lo else old.lo
                    hi = min(t for t in thresholds if t >= new.hi) if new.hi > old.hi else old.hi
                    new = IntRange(lo, hi)
                updated[value] = new
            state = updated
        # F(state) <= state was established. Simultaneous F steps preserve that
        # invariant by monotonicity, unlike publishing arbitrary worklist cuts.
        certified = state
        for _ in range(4):
            proposed = sweep(state)
            if proposed is None:
                break  # the last COMPLETE post-fixpoint remains a valid answer
            if not all(_contains(state[v], proposed[v]) for v in nodes):
                self.reason = 'invariant post-fixpoint verification failed'
                return None
            certified = state
            state = proposed
        result = certified[root]
        return result if isinstance(result, IntRange) else None
