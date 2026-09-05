"""Read-only fixtures established inside one atomic simulation group.

A creation prefix supplies the state for subsequent calls without submitting a
transaction. Original and lifted groups use the same pinned ledger round, and
must have identical transaction inputs apart from the initial approval code.
"""
from .observations import observe_simulate


def parameters(client, round, *, fee=1000):
    params = client.suggested_params()
    params.first, params.last = round, round + 1000
    params.flat_fee, params.fee = True, fee
    return params


def creation(client, approval, clear, *, sender, round, on_complete=0):
    from algosdk import transaction
    return transaction.ApplicationCreateTxn(sender, parameters(client, round), on_complete, approval, clear,
        transaction.StateSchema(32, 32), transaction.StateSchema(8, 8))


def simulate_transactions(client, txns, *, round):
    from algosdk import transaction
    from algosdk.v2client import models
    # Assign afresh: this helper also accepts a prefix simulated previously.
    for txn in txns:
        txn.group = None
    transaction.assign_group_id(txns)
    request = models.SimulateRequest(
        txn_groups=[models.SimulateRequestTransactionGroup(
            txns=[transaction.SignedTransaction(txn, None) for txn in txns])],
        round=round, allow_empty_signatures=True,
        exec_trace_config=models.SimulateTraceConfig(enable=True, scratch_change=True, state_change=True))
    response = client.simulate_transactions(request)
    if response.get('last-round') != round:
        raise ValueError('simulation used a different ledger round')
    return response


def simulate_creation(client, approval, clear, *, sender, round, on_complete=0):
    txn = creation(client, approval, clear, sender=sender, round=round, on_complete=on_complete)
    return observe_simulate(simulate_transactions(client, [txn], round=round))


def existing_app_group(client, approval, clear, steps, *, sender, round):
    """Discover the deterministic created ID, then extend the creation prefix.

    ``steps(app_id)`` constructs the subsequent transactions. The probe and the
    complete group both execute against the original ledger snapshot.
    """
    prefix = creation(client, approval, clear, sender=sender, round=round)
    prefix.note = b'tealql-fixture:\0\0'
    probe = simulate_transactions(client, [prefix], round=round)['txn-groups'][0]
    if probe.get('failure-message'):
        raise ValueError('fixture creation failed: ' + probe['failure-message'])
    app = probe['txn-results'][0]['txn-result'].get('application-index')
    if not app:
        raise ValueError('fixture creation omitted application ID')
    txns = [prefix, *steps(app)]
    # Repeated calls (for example opt-in, close-out, opt-in) still need unique
    # transaction IDs inside the group. Both variants receive the same notes.
    for index, txn in enumerate(txns):
        txn.note = b'tealql-fixture:' + index.to_bytes(2, 'big')
    return txns


def compare_groups(client, original, lifted, *, round):
    """Reject mismatched fixtures before comparing their observed effects."""
    def inputs(txns):
        rows = [dict(txn.dictify()) for txn in txns]
        if not rows or rows[0].get('type') != 'appl' or rows[0].get('apid'):
            raise ValueError('group must start with application creation')
        for row in rows:
            row.pop('grp', None)
        rows[0].pop('apap', None)
        return rows
    if inputs(original) != inputs(lifted):
        raise ValueError('original and lifted fixtures have different inputs')
    return tuple(observe_simulate(simulate_transactions(client, txns, round=round)) for txns in (original, lifted))
