"""Inferred group parties and amounts must close every relevant field."""
from itertools import product

import pytest

from tealql.security.obligations import ObligationContext, analyze_obligations
from tealql.security.payment_obligations import group_funding, payment_conservation
from tealql.tealtools.analysis.relations import LinearEqualities, affine
from tealql.tealtools.ssa import SSAProgram


def _program(*, missing=None, amount='txn Fee', fee=0, sender=None, dynamic=False):
    checks = [('global GroupSize', 'int 2'), ('txn GroupIndex', 'int 1'), ('txn OnCompletion', 'int 0'),
              ('txn RekeyTo', 'global ZeroAddress'), ('gtxn 0 TypeEnum', 'int pay'),
              ('gtxn 0 Sender', 'txn Sender'), ('gtxn 0 Receiver', 'global CurrentApplicationAddress'),
              ('gtxn 0 RekeyTo', 'global ZeroAddress'), ('gtxn 0 CloseRemainderTo', 'global ZeroAddress'),
              ('gtxn 0 Amount', 'txn Fee\nint 2\n*')]
    body = ''.join(left + '\n' + right + '\n==\nassert\n' for left, right in checks if left != missing)
    fields = ('int pay\nitxn_field TypeEnum\ntxn Sender\nitxn_field Receiver\n' +
              amount + f'\nitxn_field Amount\nint {fee}\nitxn_field Fee\n')
    if sender is not None:
        fields += sender + '\nitxn_field Sender\n'
    body += 'itxn_begin\n' + fields + 'itxn_next\n' + fields + 'itxn_submit\nint 1\nreturn\n'
    if dynamic:
        for field in ('TypeEnum', 'Sender', 'Receiver', 'RekeyTo', 'CloseRemainderTo', 'Amount'):
            body = body.replace('gtxn 0 ' + field, 'txn GroupIndex\nint 1\n-\ngtxns ' + field)
    context = ObligationContext(SSAProgram.from_text('#pragma version 10\n' + body, name='payment.teal'))
    policy = {'line': next(a.location.line for a in context.program.assignments if a.op == 'itxn_submit')}
    return context, policy


@pytest.mark.parametrize('dynamic', [False, True])
def test_infers_funding_prefix_and_linear_payment_sum(dynamic):
    context, policy = _program(dynamic=dynamic)
    assert group_funding(context, policy).status == 'PROVED'
    assert payment_conservation(context, policy).status == 'PROVED'
    assert analyze_obligations(context.program, {'funding_groups': [policy], 'payment_conservation': [policy]})['complete']


@pytest.mark.parametrize('field', ['global GroupSize', 'txn GroupIndex', 'txn OnCompletion', 'txn RekeyTo',
                                 'gtxn 0 TypeEnum', 'gtxn 0 Sender', 'gtxn 0 Receiver',
                                 'gtxn 0 RekeyTo', 'gtxn 0 CloseRemainderTo'])
def test_each_group_binding_is_required(field):
    context, policy = _program(missing=field)
    assert group_funding(context, policy).status == 'UNKNOWN'
    assert payment_conservation(context, policy).status == 'UNKNOWN'


@pytest.mark.parametrize('changes', [
    {'missing': 'gtxn 0 Amount'}, {'amount': 'txn Fee\nint 1\n+'}, {'fee': 1}, {'sender': 'txn Sender'},
])
def test_conservation_requires_actual_amounts_and_current_app_debits(changes):
    context, policy = _program(**changes)
    assert group_funding(context, policy).status == 'PROVED'
    assert payment_conservation(context, policy).status == 'UNKNOWN'


def test_linear_proofs_agree_with_finite_independent_integer_oracle():
    for multiplier in range(1, 5):
        solver = LinearEqualities([(('+' ,'x', 'y'), 'eq', ('*', multiplier, 'z')), ('x', 'eq', 'y')])
        for left, right, holds in (
            (('*', 2, 'x'), ('*', multiplier, 'z'), lambda x, y, z: 2 * x == multiplier * z),
            (('+' ,'x', ('*', 3, 'y')), ('*', 2 * multiplier, 'z'), lambda x, y, z: x + 3 * y == 2 * multiplier * z),
        ):
            assert solver.proves(left, right)
            assert all(holds(x, y, z) for x, y, z in product(range(9), repeat=3)
                       if x + y == multiplier * z and x == y)
        assert not solver.proves('x', ('+', 'y', 1))


def test_linear_contradictions_and_budgets_do_not_prove_anything():
    for premises in ([('x', 'eq', 1), ('x', 'eq', 2)],
                     [('x', 'eq', ('*', 2, 'y')), ('x', 'neq', ('*', 2, 'y'))],
                     [('x', 'eq', 'y'), ('x', 'lt', 'y')]):
        assert not LinearEqualities(premises).proves('x', 'x')
    for kwargs in ({'max_atoms': 0}, {'max_rows': 0}, {'max_bits': 1}):
        assert not LinearEqualities([('x', 'eq', 7)], **kwargs).proves('x', 7)


def test_shared_expression_dags_are_bounded_and_do_not_expand_exponentially():
    expression = 'x'
    for _ in range(30):
        expression = '+', expression, expression
    assert affine(expression) == ({'x': 2 ** 30}, 0)
    assert affine(expression, max_nodes=2) is None
    context = ObligationContext(SSAProgram.from_text('#pragma version 10\ntxn Fee\n' + 'dup\n+\n' * 30 + 'return'))
    value = next(a.inputs[0] for a in context.program.assignments if a.op == 'return')
    assert affine(context.expression(value)) == ({'txn Fee': 2 ** 30}, 0)


def test_repeated_constant_squaring_cannot_exhaust_memory_before_the_solver_budget():
    expression = 2
    for _ in range(50):
        expression = '*', expression, expression
    assert affine(expression) is None
    assert not LinearEqualities([(expression, 'eq', 'x')]).proves('x', 1)
