"""Composable numeric summaries for bounded straight-line proto routines.

Symbolic stack/frame execution preserves argument order and call identity.
Branches, recursion, unknown effects and budgets refuse the complete summary.
Answers concern successful calls; assertions are consumed without claiming they
pass. The API selects a call site explicitly because canonical callee SSA values
can represent several invocations, including earlier results saved in scratch.
"""
from dataclasses import dataclass
from math import isqrt

from ..cfg.structure import analyze_structure
from ..diagnostics.health import health_for
from ..ssa import IntRange, const_int
from ..ssa.models import _canon_shuffle
from ._range_arithmetic import _arith_result_range, _unary_result_range, _clamp_uint64
from .congruences import Congruence, TOP as UNKNOWN_RESIDUE, binary

UINT64 = IntRange(0, (1 << 64) - 1)
_BINARY = {'+', '-', '*', '/', '%', '&', '|', '^', 'shl', 'shr'}
_SHUFFLES = {'swap', 'dup', 'dup2', 'dupn', 'cover', 'uncover', 'dig', 'bury'}


@dataclass(frozen=True)
class NumericCallResult:
    bounds: IntRange | None = None
    congruence: Congruence = UNKNOWN_RESIDUE
    complete: bool = False
    reason: str = 'unsupported or exhausted numeric call summary'


@dataclass(frozen=True)
class _Parameter:
    index: int


@dataclass(frozen=True, eq=False)
class _Expression:
    # Identity-hashed DAG nodes avoid exponential tuple hashing on repeated args.
    op: str
    args: tuple


class NumericCalls:
    def __init__(self, facts):
        self.facts = facts
        self.health = health_for(facts._prog)
        structure = analyze_structure(facts._prog)
        self.subs = {s.entry_bb: s for s in structure.subroutines}
        self.sites = {s.callsub_bb: s for s in structure.call_sites}
        self.summaries, self.results = {}, {}

    def _summary(self, entry, active=frozenset()):
        if entry in active or len(active) >= 16:
            return None
        if entry in self.summaries:
            return self.summaries[entry]
        sub = self.subs.get(entry)
        proto = next((a for a in entry.assignments if a.op == 'proto'), None) if entry else None
        if sub is None or proto is None:
            return None
        try:
            arity, returns = map(int, proto.immediates.split())
        except ValueError:
            return None
        if not (0 <= arity <= 255 and 0 <= returns <= 255):
            return None
        stack = [_Parameter(i) for i in range(arity)]
        seen, block, steps = set(), entry, 0
        while block is not None and block not in seen:
            seen.add(block)
            for a in block.stack_assignments or block.assignments:
                steps += 1
                if steps > 512 or len(stack) > 512:
                    return None
                op = a.op
                if op in {'proto', 'intcblock', 'bytecblock', 'b'}:
                    continue
                if op in {'int', 'pushint', 'intc', 'intc_0', 'intc_1', 'intc_2', 'intc_3'}:
                    value = const_int(self.facts.constant(a.outputs[0])) if a.outputs else None
                    if value is None:
                        return None
                    stack.append(value)
                elif op in {'frame_dig', 'frame_bury'}:
                    try:
                        position = arity + int(a.immediates)
                    except ValueError:
                        return None
                    if op == 'frame_bury':
                        if not stack:
                            return None
                        value = stack.pop()
                        if position == len(stack):
                            stack.append(value)
                        elif 0 <= position < len(stack):
                            stack[position] = value
                        else:
                            return None
                    elif 0 <= position < len(stack):
                        stack.append(stack[position])
                    else:
                        return None
                elif op in _SHUFFLES:
                    count, mapping = _canon_shuffle(op, a.immediates)
                    if mapping is None or count > len(stack):
                        return None
                    inputs = [stack.pop() for _ in range(count)]
                    stack.extend(reversed([inputs[i] for i in mapping]))
                elif op in _BINARY | {'~', 'sqrt', 'pop', 'assert'}:
                    count = 2 if op in _BINARY else 1
                    if len(stack) < count:
                        return None
                    args = tuple(stack[-count:])
                    del stack[-count:]
                    if op not in {'pop', 'assert'}:
                        stack.append(_Expression(op, args))
                elif op == 'callsub':
                    site = self.sites.get(block)
                    nested = self._summary(site.target_entry, active | {entry}) if site else None
                    if nested is None or len(stack) < nested[0]:
                        return None
                    count, expressions = nested
                    arguments = stack[-count:] if count else []
                    if count:
                        del stack[-count:]
                    memo = {}
                    def bind(expression, depth=0):
                        if depth > 64 or len(memo) > 256:
                            raise ValueError('numeric expression budget')
                        if isinstance(expression, _Parameter):
                            return arguments[expression.index]
                        if not isinstance(expression, _Expression):
                            return expression
                        if expression not in memo:
                            memo[expression] = _Expression(expression.op, tuple(bind(v, depth + 1) for v in expression.args))
                        return memo[expression]
                    try:
                        stack.extend(bind(v) for v in expressions)
                    except ValueError:
                        return None
                elif op == 'retsub':
                    if len(stack) != arity + returns:
                        return None
                    result = arity, tuple(stack[arity:])
                    self.summaries[entry] = result
                    return result
                else:
                    return None
            if block in self.sites:
                block = self.sites[block].continuation_bb
            else:
                successors = [b for b in block.successors if b in sub.body]
                block = successors[0] if len(successors) == 1 else None
        return None

    def query(self, call, slot=0):
        if self.facts._prog.revision != self.facts.revision:
            raise RuntimeError('stale facts: request facts again after changing the program')
        if not self.health.complete:
            return NumericCallResult(reason='program representation is incomplete')
        key = call, slot
        if key in self.results:
            return self.results[key]
        site = self.sites.get(call.basic_block) if call.op == 'callsub' else None
        summary = self._summary(site.target_entry) if site else None
        if summary is None or not 0 <= slot < len(summary[1]) or len(call.inputs) != summary[0]:
            return NumericCallResult()
        arguments = [(self.facts.range_at(v, call), self.facts.congruence(v))
                     for v in reversed(call.inputs)]
        memo = {}

        def evaluate(expression, depth=0):
            if depth > 64 or len(memo) > 256:
                raise ValueError('numeric expression budget')
            if type(expression) is int:
                return IntRange(expression, expression), Congruence(0, expression)
            if isinstance(expression, _Parameter):
                return arguments[expression.index]
            if expression in memo:
                return memo[expression]
            args = [evaluate(v, depth + 1) for v in expression.args]
            ranges, residues = zip(*args)
            ranges = [r or UINT64 for r in ranges]  # numeric op enforces type on success
            op = expression.op
            if len(args) == 2:
                bounds = _arith_result_range(op, *ranges)
                residue = binary(op, *residues)
            else:
                bounds = _unary_result_range(op, ranges[0])
                residue = (Congruence(residues[0].modulus, UINT64.hi - residues[0].residue)
                           if op == '~' else Congruence(0, isqrt(ranges[0].lo))
                           if ranges[0].lo == ranges[0].hi else UNKNOWN_RESIDUE)
            if bounds is None:
                result = None, UNKNOWN_RESIDUE
            else:
                lo, hi = _clamp_uint64(*bounds)
                result = residue.reduce(IntRange(lo, hi)) if lo <= hi else None, residue
            memo[expression] = result
            return result
        try:
            bounds, residue = evaluate(summary[1][slot])
        except ValueError:
            return NumericCallResult()
        result = NumericCallResult(bounds, residue, bounds is not None,
            'numeric return on successful executions of this call' if bounds else
            'no numeric successful result established')
        self.results[key] = result
        return result
