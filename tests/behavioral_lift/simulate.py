"""Read-only creation fixtures for current algod (dryrun was removed in v5).

Both programs simulate against the same pinned ledger round. This covers only
creation behavior; an existing-app comparison needs a supplied ledger fixture.
"""
from .observations import observe_simulate


def simulate_creation(client, approval, clear, *, sender, round, on_complete=0):
    from algosdk import transaction
    from algosdk.v2client import models
    params = client.suggested_params()
    params.first, params.last = round, round + 1000
    params.flat_fee, params.fee = True, 1000
    txn = transaction.ApplicationCreateTxn(sender, params, on_complete, approval, clear,
        transaction.StateSchema(32, 32), transaction.StateSchema(8, 8))
    request = models.SimulateRequest(
        txn_groups=[models.SimulateRequestTransactionGroup(
            txns=[transaction.SignedTransaction(txn, None)])],
        round=round, allow_empty_signatures=True,
        exec_trace_config=models.SimulateTraceConfig(enable=True, scratch_change=True, state_change=True))
    response = client.simulate_transactions(request)
    if response.get('last-round') != round:
        raise ValueError('simulation used a different ledger round')
    return observe_simulate(response)
