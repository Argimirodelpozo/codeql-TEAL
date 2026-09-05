"""Below-frame values checked against concrete list and integer semantics."""
import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram


def _concrete(body):
    stack = [11, 22, 33, 44]
    for instruction in body.splitlines():
        op, *args = instruction.split()
        n = int(args[0]) if args else None
        if op == 'int':
            stack.append(n)
        elif op == 'cover':
            value = stack.pop()
            stack.insert(len(stack) - n, value)
        elif op == 'uncover':
            stack.append(stack.pop(-n - 1))
        elif op == 'dig':
            stack.append(stack[-n - 1])
        elif op == 'bury':
            value = stack.pop()
            stack[-n] = value
        elif op == 'swap':
            stack[-2:] = reversed(stack[-2:])
        elif op == 'dup2':
            stack.extend(stack[-2:])
        elif op == 'dupn':
            stack.extend([stack[-1]] * n)
        elif op in {'mulw', 'addw'}:
            right, left = stack.pop(), stack.pop()
            wide = left * right if op == 'mulw' else left + right
            stack.extend(divmod(wide, 2 ** 64))
        elif op == 'frame_dig':
            stack.append(stack[4 + n])
        elif op == 'frame_bury':
            stack[4 + n] = stack.pop()
        else:
            raise AssertionError(op)
    assert len(stack) >= 4
    # proto 1 0 removes the one argument and every callee temporary.
    return list(reversed(stack[:3]))


@pytest.mark.parametrize('body', [
    'int 55\ncover 2', 'int 55\ncover 3', 'int 55\ncover 4',
    'uncover 1', 'uncover 2', 'uncover 3',
    'dig 3', 'bury 1\nint 0', 'bury 3\nint 0', 'swap', 'dup2',
    'uncover 3\ndupn 2\ncover 4',
    'frame_dig -1\ncover 4', 'int 66\nframe_bury -1\nuncover 3',
    'int 2\nint 3\nmulw\ncover 4',
    'int 18446744073709551615\nint 3\naddw\ncover 4',
])
def test_caller_residual_matches_concrete_stack(body):
    source = ('#pragma version 10\nint 11\nint 22\nint 33\nint 44\ncallsub helper\n'
              'itob\nlog\nitob\nlog\nitob\nlog\nint 1\nreturn\n'
              'helper:\nproto 1 0\n' + body + '\nretsub\n')
    prog = SSAProgram.from_text(source, name='callee-oracle.teal')
    if body not in {'dig 3', 'dup2'}:  # Pure copies do not require a clobber summary.
        assert prog._pyssa._effect_summaries, 'fixture must exercise residual summaries'
    facts = prog.facts(FactDomain.CONSTANTS)
    def value(operand):
        constant = facts.constant(operand)
        if constant is not None:
            return int(constant.value)
        # Independently evaluate an unfurled wide output if folding is disabled.
        operation = operand.defined_by
        assert operation.op in {'mulw', 'addw'}
        right, left = (value(item) for item in operation.inputs)
        wide = left * right if operation.op == 'mulw' else left + right
        high, low = divmod(wide, 2 ** 64)
        return (low, high)[operation.outputs.index(operand)]
    actual = [value(a.inputs[0]) for a in prog.assignments if a.op == 'itob']
    assert actual == _concrete(body)


@pytest.mark.parametrize('body', [
    'callsub nested\nint 55\ncover 4\nretsub\nnested:\nproto 0 0\nretsub',
    'txn NumAppArgs\nbz join\nint 55\ncover 4\njoin:\nretsub',
    'again:\nint 55\ncover 4\ntxn NumAppArgs\nbnz again\nretsub',
    'int 55\ncover 4\nframe_dig -2\nretsub',
    'int 55\ncover 4\nframe_bury -2\nretsub',
    'int 55\ncover 4\npop\npop\nretsub',
])
def test_unmodelled_or_rejecting_callees_do_not_publish_partial_summaries(body):
    source = ('#pragma version 10\nint 11\nint 22\nint 33\nint 44\ncallsub helper\n'
              'int 1\nreturn\nhelper:\nproto 1 0\n' + body + '\n')
    prog = SSAProgram.from_text(source, name='callee-limit.teal')
    assert not prog._pyssa._effect_summaries
