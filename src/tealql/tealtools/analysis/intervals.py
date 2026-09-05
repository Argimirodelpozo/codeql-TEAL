"""Bounded interval queries using the canonical predicates at each use.

Arithmetic is evaluated at its defining instruction. Phi arms join; recursive
value webs widen to uint64 top. The visit budget bounds adversarial graph depth
without turning an incomplete traversal into a narrow interval.
"""
from __future__ import annotations

from ..ssa import Const, IntRange, Phi, SSAVar, const_int
from ..language.spec import result_type
from ._range_arithmetic import _arith_result_range, _unary_result_range, _clamp_uint64
from ._range_refinement import _apply

TOP = IntRange(0, (1 << 64) - 1)
_REL = {'eq': '==', 'neq': '!=', 'lt': '<', 'le': '<=', 'gt': '>', 'ge': '>='}
_FLIP = {'==': '==', '!=': '!=', '<': '>', '>': '<', '<=': '>=', '>=': '<='}


def _meet(left, right):
    if left is None:
        return right
    if right is None:
        return left
    lo, hi = max(left.lo, right.lo), min(left.hi, right.hi)
    return IntRange(lo, hi) if lo <= hi else None


class IntervalQuery:
    def __init__(self, facts, *, budget=128):
        from ..cfg.path_predicates import PathPredicateAnalysis
        self.facts = facts
        self.predicates = PathPredicateAnalysis(facts._prog)
        self.budget = budget
        self.cache = {}
        self.visits = self.widenings = 0

    def _key(self, value):
        from .context import _value_key
        return self.facts._resolved_key(value) or _value_key(value)

    def _bounds(self, value):
        n = const_int(self.facts.constant(value))
        if n is not None:
            return IntRange(n, n)
        return self.facts.int_range(value)

    def _refine(self, value, current, file, line):
        key = self._key(value)
        for predicate in self.predicates.predicates_at(file, line):
            rel = _REL.get(predicate.kind)
            left, right = predicate.value, predicate.args[0] if predicate.args else None
            if predicate.kind in {'zero', 'nonzero'}:
                rel = '==' if predicate.kind == 'zero' else '!='
                other = IntRange(0, 0)
            else:
                other = self._bounds(right) if right is not None else None
            if rel is None:
                continue
            if self._key(left) != key:
                if right is None or self._key(right) != key:
                    continue
                other = self._bounds(left)
                rel = _FLIP[rel]
            if other is None:
                continue
            # A bytes comparison is not an integer relation. A numeric RHS or
            # truthiness is the required AVM type evidence for a polymorphic op.
            lo, hi = _apply(rel, current or TOP, other)
            if lo > hi:
                return None, False
            current = IntRange(lo, hi)
        return current, True

    def range_at(self, value, target):
        if hasattr(target, 'location'):
            file, line = target.location.file, target.location.line
        else:
            block, line = target
            if block is None:
                return self._bounds(value)
            file = block.file
        self.visits = self.widenings = 0
        return self._query(value, file, line, set())

    def _query(self, value, file, line, active):
        if isinstance(value, Const):
            return self._bounds(value)
        value = self.facts.resolve(value)
        key = self._key(value)
        if key is None:
            return self._bounds(value)
        if key[1] != file:
            return None
        base, reachable = self._refine(value, self._bounds(value), file, line)
        if not reachable:
            return None
        cache_key = key, file, line
        if cache_key in self.cache:
            return self.cache[cache_key]
        self.visits += 1
        if key in active or self.visits > self.budget:
            self.widenings += 1
            return base
        active.add(key)
        derived = None
        try:
            if isinstance(value, Phi) and value.args:
                arms = [self._query(a, file, line, active) for a in value.args]
                if all(a is not None for a in arms):
                    derived = IntRange(min(a.lo for a in arms), max(a.hi for a in arms))
            elif isinstance(value, SSAVar) and value.defined_by is not None:
                assignment = value.defined_by
                location = assignment.location
                def operand(v):
                    return self._query(v, location.file, location.line, active) or TOP
                bounds = None
                if len(assignment.outputs) == 1:
                    if assignment.op in {'+', '-', '*', '/', '%', '&', '|', '^', 'shl', 'shr'} and len(assignment.inputs) == 2:
                        bounds = _arith_result_range(assignment.op, operand(assignment.inputs[1]), operand(assignment.inputs[0]))
                    elif assignment.op in {'~', 'sqrt'} and len(assignment.inputs) == 1:
                        bounds = _unary_result_range(assignment.op, operand(assignment.inputs[0]))
                if bounds is not None:
                    lo, hi = _clamp_uint64(*bounds)
                    if lo <= hi:
                        derived = IntRange(lo, hi)
                elif result_type(assignment.op, value.index - 1) in {'uint64', 'bool'}:
                    derived = TOP
            result = _meet(base, derived)
            self.cache[cache_key] = result
            return result
        finally:
            active.remove(key)
