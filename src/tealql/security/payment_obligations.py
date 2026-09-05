"""Infer a closed payment-funding prefix and its inner payment conservation."""
from __future__ import annotations

from tealql.tealtools.analysis.relations import DifferenceConstraints, LinearEqualities
from tealql.tealtools.reporting.inner_transactions import InnerTxnReport

_ZERO = 'bytes:0x' + '00' * 32


def _funding(context, line):
    if len(context.program.assignments) > 4096:
        return None
    premises = tuple(context.premises(line))
    solver = DifferenceConstraints(premises)
    size = solver.interval('global GroupSize')
    if not context.health.complete or size is None or not 2 <= size[0] == size[1] <= 16:
        return None
    size = size[0]
    checks = [('txn GroupIndex', 'eq', size - 1), ('txn OnCompletion', 'eq', 0),
              ('txn RekeyTo', 'eq', _ZERO)]
    for index in range(size - 1):
        checks.extend((f'gtxn {index} {field}', 'eq', value) for field, value in (
            ('TypeEnum', 1), ('Sender', 'txn Sender'), ('Receiver', 'global CurrentApplicationAddress'),
            ('CloseRemainderTo', _ZERO), ('RekeyTo', _ZERO)))
    if not all(solver.proves(*check) for check in checks):
        return None
    return size, premises


def group_funding(context, policy):
    funding = _funding(context, policy['line'])
    return context.result('group-funding', str(policy['line']), policy['line'], funding is not None,
        f'{funding[0] - 1} preceding payments fund the current app from the caller; no close or rekey fields'
        if funding else 'group size, position, member types, parties, or close/rekey guards are unproved',
        ('the program executes as an application approval; fees and intended amounts are separate obligations',))


def payment_conservation(context, policy):
    """Infer amounts from a single-block inner group, then prove their sum.

    This is an equality of gross ALGO transfers, conditional on success. It is
    not a claim about recipient authorization, spendable balance, or all paths.
    """
    line = policy['line']
    funding = _funding(context, line)
    submit = context.by_line.get(line)
    groups = [group for group in InnerTxnReport(context.program).groups if group.submit_line == line]
    ok = bool(funding and submit and submit.op == 'itxn_submit' and len(groups) == 1 and 1 <= len(groups[0].txns) <= 16)
    total = 0
    if ok:
        group = groups[0]
        boundaries = [a for a in submit.basic_block.stack_assignments
                      if group.txns[0].begin_line <= a.location.line <= line and a.op in {'itxn_begin', 'itxn_next', 'itxn_submit'}]
        ok &= (len(boundaries) == len(group.txns) + 1 and boundaries[0].op == 'itxn_begin'
               and boundaries[-1].op == 'itxn_submit' and all(a.op == 'itxn_next' for a in boundaries[1:-1]))
        for txn in group.txns:
            fields = txn.fields_by_name()
            ok &= all(len(values) == 1 for values in fields.values())
            ok &= set(fields) <= {'TypeEnum', 'Sender', 'Receiver', 'Amount', 'Fee', 'CloseRemainderTo', 'RekeyTo', 'Note'}
            ok &= all(context.by_line[field.line].basic_block == submit.basic_block for field in txn.fields)
            def expression(name, default=None):
                return context.expression(fields[name][0].operand) if name in fields else default
            ok &= expression('TypeEnum') == 1 and expression('Fee') == 0
            ok &= expression('Sender', 'global CurrentApplicationAddress') == 'global CurrentApplicationAddress'
            ok &= expression('CloseRemainderTo', _ZERO) == _ZERO and expression('RekeyTo', _ZERO) == _ZERO
            ok &= expression('Receiver') is not None
            amount = expression('Amount', 0)
            ok &= amount is not None
            total = '+', total, amount
        incoming = 0
        for index in range(funding[0] - 1):
            incoming = '+', incoming, f'gtxn {index} Amount'
        ok &= LinearEqualities(funding[1]).proves(total, incoming)
    return context.result('payment-conservation', str(line), line, ok,
        'inferred funding amounts equal the sum of current-app inner payment amounts with zero inner fees'
        if ok else 'funding closure, single-block inner fields, or linear amount equality is unproved',
        ('the program executes as an application approval; recipient authorization and external fee sufficiency are separate',))
