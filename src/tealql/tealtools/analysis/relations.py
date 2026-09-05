"""Bounded difference constraints over mathematical integers.

Only x - y <= c is admitted. Unsupported expressions and inconsistent premises
return unknown, rather than proving arbitrary statements by contradiction.
Callers are responsible for tying atoms to exact, immutable value identities.
"""
from __future__ import annotations

from fractions import Fraction


def affine(expression, *, max_nodes=256, max_bits=4096):
    """Normalize a bounded expression DAG without expanding shared subtrees."""
    memo = {}
    remaining = max_nodes

    def visit(expression, depth=0):
        nonlocal remaining
        if remaining <= 0 or depth > 64:
            return None
        if type(expression) is int:
            return ({}, expression) if expression.bit_length() <= max_bits else None
        if isinstance(expression, str):
            return {expression: 1}, 0
        if not isinstance(expression, tuple) or len(expression) != 3:
            return None
        key = id(expression)
        if key in memo:
            return memo[key]
        remaining -= 1
        op, left, right = expression
        a, b = visit(left, depth + 1), visit(right, depth + 1)
        if a is None or b is None or op not in {'+', '-', '*'}:
            return None
        if op == '*':
            if a[0] and b[0]:
                return None
            scalar, other = (a[1], b) if not a[0] else (b[1], a)
            result = {k: v * scalar for k, v in other[0].items() if v * scalar}, other[1] * scalar
        else:
            sign = 1 if op == '+' else -1
            coeffs = dict(a[0])
            for key, coefficient in b[0].items():
                coeffs[key] = coeffs.get(key, 0) + sign * coefficient
            result = {k: v for k, v in coeffs.items() if v}, a[1] + sign * b[1]
        if any(value.bit_length() > max_bits for value in (*result[0].values(), result[1])):
            return None
        memo[id(expression)] = result
        return result

    return visit(expression)


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


class LinearEqualities:
    """Bounded rational elimination proving integer linear identities.

    Rational solutions overapproximate integer solutions. No witness is claimed;
    a goal is proved only when it follows from all admitted equality rows.
    Detected contradictions, exhaustion, and oversized coefficients refuse.
    """

    def __init__(self, premises=(), *, max_atoms=64, max_rows=256, max_bits=512):
        self.rows = {}
        self.complete = True
        self.consistent = True
        self.max_bits = max_bits
        atoms, deferred = set(), []
        for index, (left, relation, right) in enumerate(premises):
            if index >= max_rows:
                self.complete = False
                break
            result = affine(('-', left, right))
            if result is None:
                continue
            coefficients, offset = result
            atoms.update(coefficients)
            if len(atoms) > max_atoms:
                self.complete = False
                break
            row = {key: Fraction(value) for key, value in coefficients.items()}
            if offset:
                row[None] = Fraction(offset)
            if not self._bounded(row):
                break
            if relation != 'eq':
                deferred.append((row, relation))
                continue
            row = self._reduce(row)
            variables = sorted(key for key in row if key is not None)
            if not variables:
                self.consistent &= not row.get(None, 0)
            else:
                pivot = variables[0]
                divisor = row[pivot]
                row = {key: value / divisor for key, value in row.items()}
                if not self._bounded(row):
                    break
                self.rows[pivot] = row
        # A guard reduced to a false constant is an explicit contradiction.
        for row, relation in deferred:
            row = self._reduce(row)
            if any(key is not None for key in row):
                continue
            value = row.get(None, 0)
            checks = {'neq': value != 0, 'le': value <= 0, 'lt': value < 0,
                      'ge': value >= 0, 'gt': value > 0}
            self.consistent &= checks.get(relation, True)

    def _bounded(self, row):
        if any(max(value.numerator.bit_length(), value.denominator.bit_length()) > self.max_bits
               for value in row.values()):
            self.complete = False
        return self.complete

    def _reduce(self, row):
        row = dict(row)
        for pivot, known in sorted(self.rows.items()):
            factor = row.get(pivot, 0)
            if not factor:
                continue
            for key, value in known.items():
                row[key] = row.get(key, 0) - factor * value
                if row[key] == 0:
                    del row[key]
            if not self._bounded(row):
                break
        return row

    def proves(self, left, right):
        result = affine(('-', left, right))
        if result is None or not self.complete or not self.consistent:
            return False
        coefficients, offset = result
        row = {key: Fraction(value) for key, value in coefficients.items()}
        if offset:
            row[None] = Fraction(offset)
        if not self._bounded(row):
            return False
        reduced = self._reduce(row)
        return self.complete and not reduced
