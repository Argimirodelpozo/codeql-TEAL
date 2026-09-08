"""Small concrete TEAL machine for generated loop tests; no analysis imports."""
from collections import Counter
from dataclasses import dataclass


@dataclass
class Execution:
    logs: list[int]
    visits: Counter
    cost: int
    outcome: str


def execute(text, *, fields=None, credit=1_000_000, max_steps=4096):
    ops, labels = [], {}
    for raw in text.splitlines():
        line = raw.split('//')[0].strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith(':'):
            labels[line[:-1]] = len(ops)
        else:
            ops.append(line.split())
    at = {}
    for label, index in labels.items():
        at.setdefault(index, []).append(label)
    stack, scratch, calls, logs = [], [0] * 256, [], []
    visits = Counter()
    pc = cost = 0
    fields = fields or {}
    for _ in range(max_steps):
        if pc >= len(ops):
            return Execution(logs, visits, cost, 'off-end')
        visits.update(at.get(pc, ()))
        op, *args = ops[pc]
        pc += 1
        cost += 1
        if cost > credit:
            return Execution(logs, visits, cost, 'budget')
        if op == 'int':
            stack.append(int(args[0]))
        elif op == 'txn':
            stack.append(fields.get(args[0], 0))
        elif op == 'global':
            assert args == ['OpcodeBudget']
            stack.append(credit - cost)
        elif op == 'dup':
            stack.append(stack[-1])
        elif op == 'dig':
            stack.append(stack[-int(args[0]) - 1])
        elif op == 'swap':
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 'pop':
            stack.pop()
        elif op == 'store':
            scratch[int(args[0])] = stack.pop()
        elif op == 'load':
            stack.append(scratch[int(args[0])])
        elif op == 'stores':
            value, slot = stack.pop(), stack.pop()
            scratch[slot] = value
        elif op in {'+', '-', '*', '%', '<', '<=', '>', '>=', '==', '!='}:
            right, left = stack.pop(), stack.pop()
            if op == '%':
                if right == 0:
                    return Execution(logs, visits, cost, 'arithmetic')
                value = left % right
            else:
                value = {
                    '+': lambda: left + right, '-': lambda: left - right,
                    '*': lambda: left * right, '<': lambda: int(left < right),
                    '<=': lambda: int(left <= right), '>': lambda: int(left > right),
                    '>=': lambda: int(left >= right), '==': lambda: int(left == right),
                    '!=': lambda: int(left != right),
                }[op]()
            if not 0 <= value < 2**64:
                return Execution(logs, visits, cost, 'arithmetic')
            stack.append(value)
        elif op in {'b', 'bz', 'bnz'}:
            take = True if op == 'b' else bool(stack.pop()) == (op == 'bnz')
            if take:
                pc = labels[args[0]]
        elif op == 'callsub':
            calls.append(pc)
            pc = labels[args[0]]
        elif op == 'retsub':
            pc = calls.pop()
        elif op == 'assert':
            if not stack.pop():
                return Execution(logs, visits, cost, 'assert')
        elif op == 'itob':
            stack.append(stack.pop().to_bytes(8, 'big'))
        elif op == 'log':
            logs.append(int.from_bytes(stack.pop(), 'big'))
        elif op == 'return':
            return Execution(logs, visits, cost, 'approve' if stack.pop() else 'reject')
        elif op == 'err':
            return Execution(logs, visits, cost, 'err')
        else:
            raise AssertionError(f'unsupported oracle opcode: {op}')
    return Execution(logs, visits, cost, 'step-limit')
