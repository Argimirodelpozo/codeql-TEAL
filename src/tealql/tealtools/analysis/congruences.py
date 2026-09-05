"""Bounded inductive congruences, reduced with uint64 intervals at query sites.

``m, r`` denotes integers congruent to r modulo m; m=0 is an exact integer,
m=1 is unknown. Equations start at bottom and grow by join. No intermediate
iterate escapes: exhaustion returns top, and unseeded cycles remain unknown.
Arithmetic describes successful AVM executions; shl explicitly models wrapping.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from math import gcd

from ..ssa import IntRange, Phi, const_int

MASK = (1 << 64) - 1


@dataclass(frozen=True)
class Congruence:
    modulus: int = 1
    residue: int = 0

    def __post_init__(self):
        if self.modulus < 0:
            raise ValueError('congruence modulus must be nonnegative')
        if self.modulus:
            object.__setattr__(self, 'residue', self.residue % self.modulus)

    def join(self, other):
        return Congruence(gcd(self.modulus, other.modulus, self.residue - other.residue), self.residue)

    def divisible_by(self, divisor):
        return divisor > 0 and self.modulus % divisor == 0 and self.residue % divisor == 0

    def reduce(self, interval):
        if interval is None:
            return None
        lo, hi = interval.lo, interval.hi
        if self.modulus == 0:
            lo, hi = max(lo, self.residue), min(hi, self.residue)
        else:
            lo += (self.residue - lo) % self.modulus
            hi -= (hi - self.residue) % self.modulus
        return IntRange(lo, hi) if lo <= hi else None

    def bits(self):
        # The power-of-two factor of m fixes exactly this low-bit prefix.
        mask = MASK if not self.modulus else (self.modulus & -self.modulus) - 1
        mask &= MASK
        return self.residue & mask, ~self.residue & mask  # known one, known zero


TOP = Congruence()


def binary(op, a, b):
    if op == '+':
        return Congruence(gcd(a.modulus, b.modulus), a.residue + b.residue)
    if op == '-':
        return Congruence(gcd(a.modulus, b.modulus), a.residue - b.residue)
    if op == '*':
        return Congruence(gcd(a.modulus * b.modulus, a.modulus * b.residue,
                              b.modulus * a.residue), a.residue * b.residue)
    if b.modulus == 0:
        n = b.residue
        if op == '%' and n > 0:
            return (Congruence(0, a.residue % n) if not a.modulus
                    else Congruence(gcd(a.modulus, n), a.residue))
        if op == '/' and n > 0 and a.modulus % n == 0:
            return Congruence(a.modulus // n, a.residue // n)
        if op == 'shl' and 0 <= n < 64:
            return Congruence(gcd(a.modulus << n, 1 << 64), a.residue << n)
        if op == 'shr' and 0 <= n < 64:
            return binary('/', a, Congruence(0, 1 << n))
    if op in {'&', '|', '^'}:
        a1, a0 = a.bits()
        b1, b0 = b.bits()
        if op == '&':
            one, zero = a1 & b1, a0 | b0
        elif op == '|':
            one, zero = a1 | b1, a0 & b0
        else:
            one, zero = (a1 & b0) | (a0 & b1), (a1 & b1) | (a0 & b0)
        unknown = MASK & ~(one | zero)
        return (Congruence(0, one) if not unknown
                else Congruence(unknown & -unknown, one))
    return TOP


class CongruenceQuery:
    def __init__(self, facts, *, budget=128, steps=4096):
        self.facts, self.budget, self.steps = facts, budget, steps
        self.cache = {}
        self.exhausted = False

    def _equation(self, value):
        n = const_int(self.facts.constant(value))
        if n is not None:
            return Congruence(0, n), ()
        if isinstance(value, Phi) and value.args:
            return 'join', tuple(value.args)
        assignment = getattr(value, 'defined_by', None)
        if assignment and len(assignment.outputs) == 1:
            op, args = assignment.op, assignment.inputs
            if op in {'+', '-', '*', '/', '%', '&', '|', '^', 'shl', 'shr'} and len(args) == 2:
                return op, tuple(reversed(args))
            if op in {'~', 'frame_dig'} and len(args) == 1:
                return op, tuple(args)
        return TOP, ()

    def query(self, value):
        value = self.facts.resolve(value)  # also rejects stale revisions
        if value in self.cache:
            return self.cache[value]
        self.exhausted = False
        equations, dependents, work = {}, {}, [value]
        while work:
            node = self.facts.resolve(work.pop())
            if node in equations:
                continue
            if len(equations) >= self.budget:
                self.exhausted = True
                return TOP
            op, children = self._equation(node)
            children = tuple(self.facts.resolve(v) for v in children)
            equations[node] = op, children
            for child in children:
                dependents.setdefault(child, set()).add(node)
            work.extend(children)
        states = dict.fromkeys(equations)  # None is bottom, not unknown
        queue, pending = deque(equations), set(equations)
        steps = 0
        seed_unknown = True
        while queue or seed_unknown:
            if not queue:
                seed_unknown = False
                for node, result in states.items():
                    if result is None:
                        states[node] = TOP
                        for dependent in dependents.get(node, ()):
                            if dependent not in pending:
                                queue.append(dependent)
                                pending.add(dependent)
                if not queue:
                    break
            if steps >= self.steps:
                self.exhausted = True
                return TOP
            steps += 1
            node = queue.popleft()
            pending.remove(node)
            op, children = equations[node]
            args = [states[v] for v in children]
            result = None
            if isinstance(op, Congruence):
                result = op
            elif op == 'join':
                for arg in args:
                    if arg is not None:
                        result = arg if result is None else result.join(arg)
            elif all(a is not None for a in args):
                if op == 'frame_dig':
                    result = args[0]
                elif op == '~':
                    result = Congruence(args[0].modulus, MASK - args[0].residue)
                else:
                    result = binary(op, *args)
            if result is None:
                continue
            if states[node] is not None:
                result = states[node].join(result)
            if result != states[node]:
                states[node] = result
                for dependent in dependents.get(node, ()):
                    if dependent not in pending:
                        queue.append(dependent)
                        pending.add(dependent)
        # Every installed result is a post-fixpoint of the complete equations.
        self.cache.update({node: result or TOP for node, result in states.items()})
        return self.cache[value]
