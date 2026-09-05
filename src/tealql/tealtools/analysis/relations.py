"""Bounded difference constraints over mathematical integers.

Only x - y <= c is admitted. Unsupported expressions and inconsistent premises
return unknown, rather than proving arbitrary statements by contradiction.
Callers are responsible for tying atoms to exact, immutable value identities.
"""
from __future__ import annotations


def affine(expression):
    if type(expression) is int:
        return {}, expression
    if isinstance(expression, str):
        return {expression: 1}, 0
    if not isinstance(expression, tuple) or len(expression) != 3:
        return None
    op, left, right = expression
    a, b = affine(left), affine(right)
    if a is None or b is None or op not in {'+', '-', '*'}:
        return None
    if op == '*':
        if a[0] and b[0]:
            return None
        scalar, other = (a[1], b) if not a[0] else (b[1], a)
        return {k: v * scalar for k, v in other[0].items() if v * scalar}, other[1] * scalar
    sign = 1 if op == '+' else -1
    coeffs = dict(a[0])
    for key, coefficient in b[0].items():
        coeffs[key] = coeffs.get(key, 0) + sign * coefficient
    return {k: v for k, v in coeffs.items() if v}, a[1] + sign * b[1]


def _bound(left, right, strict=False):
    result = affine(('-', left, right))
    if result is None:
        return None
    coeffs, offset = result
    positive = [k for k, v in coeffs.items() if v == 1]
    negative = [k for k, v in coeffs.items() if v == -1]
    if len(positive) > 1 or len(negative) > 1 or len(positive) + len(negative) != len(coeffs):
        return None
    return (positive[0] if positive else None, negative[0] if negative else None,
            -offset - int(strict))


class DifferenceConstraints:
    def __init__(self, premises=(), *, max_atoms=64):
        self.bounds = {}
        self.atoms = {None}
        self.max_atoms = max_atoms
        self.truncated = False
        for left, relation, right in premises:
            if relation in {'eq', 'le', 'lt'}:
                self._add(_bound(left, right, relation == 'lt'))
            if relation in {'eq', 'ge', 'gt'}:
                self._add(_bound(right, left, relation == 'gt'))
        self._close()

    def _add(self, bound):
        if bound is None:
            return
        x, y, c = bound
        if len(self.atoms | {x, y}) > self.max_atoms:
            self.truncated = True
            return
        self.atoms.update((x, y))
        self.bounds[x, y] = min(c, self.bounds.get((x, y), c))

    def _close(self):
        for x in self.atoms:
            self.bounds[x, x] = min(0, self.bounds.get((x, x), 0))
        for k in self.atoms:
            for x in self.atoms:
                a = self.bounds.get((x, k))
                if a is None:
                    continue
                for y in self.atoms:
                    b = self.bounds.get((k, y))
                    if b is not None:
                        self.bounds[x, y] = min(a + b, self.bounds.get((x, y), a + b))

    @property
    def consistent(self):
        return all(self.bounds[x, x] >= 0 for x in self.atoms)

    def proves(self, left, relation, right):
        if not self.consistent or self.truncated or left is None or right is None:
            return False
        if relation == 'eq':
            return self.proves(left, 'le', right) and self.proves(right, 'le', left)
        if relation in {'gt', 'ge'}:
            return self.proves(right, 'lt' if relation == 'gt' else 'le', left)
        if relation not in {'le', 'lt'}:
            return False
        bound = _bound(left, right, relation == 'lt')
        if bound is None:
            return False
        x, y, c = bound
        if x == y:
            return 0 <= c
        return self.bounds.get((x, y), float('inf')) <= c

    def interval(self, expression):
        """Finite bounds on a supported difference, or None when unproved."""
        if not self.consistent or self.truncated:
            return None
        upper, lower = _bound(expression, 0), _bound(0, expression)
        if upper is None or lower is None:
            return None
        x, y, offset = upper
        hi = self.bounds.get((x, y))
        lo = self.bounds.get((lower[0], lower[1]))
        return (lower[2] - lo, hi - offset) if lo is not None and hi is not None else None
