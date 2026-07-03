"""Refined appcall flow-functions: the cross-contract taint bridges carry only
CERTAIN values across the boundary. Beyond the original ``txna ApplicationArgs``
forward channel these tests pin two refinements:

  1. the arg channel also bridges the ``txn ApplicationArgs N`` read form (not
     just ``txna``), the same gap fixed for ``seeds_for_callee``; and
  2. the FOREIGN-ARRAY forward channel (``itxn_field {Accounts,Assets,
     Applications}`` -> the callee's positional ``txn``/``txna`` read) with the
     AVM implicit-entry offset — the callee's ``Accounts 0`` is its Sender and
     ``Applications 0`` is the current app, so the caller's first pushed entry
     is read by the callee at index 1, NOT 0.
"""
from helpers import make_xcontract
from tealql.tealtools.dataflow.xcontract_taint_graph import (
    XContractTaintGraph, cross_taint_findings,
)


def _bridge_edges(xtg, kind):
    """(caller_node, callee_node) pairs carrying the given bridge kind."""
    return [
        (u, v) for u, v, data in xtg.g.edges(data=True)
        if kind in data.get("kinds", ())
    ]


def _build(tmp_path, caller_src, callee_src, *, app=100):
    caller, registry = make_xcontract(tmp_path, caller_src, {app: callee_src})
    return XContractTaintGraph.build(caller, registry)


# --- (1) arg channel: the txn ApplicationArgs N read form ----------------

_ARG_CALLER = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field ApplicationArgs
itxn_submit
int 1
return
"""
# Callee reads its arg via `txn ApplicationArgs 0` (NOT txna) and pays it out.
_ARG_CALLEE_TXN_FORM = """#pragma version 10
itxn_begin
txn ApplicationArgs 0
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def test_arg_bridge_reaches_txn_form_read(tmp_path):
    xtg = _build(tmp_path, _ARG_CALLER, _ARG_CALLEE_TXN_FORM)
    # the appcall-arg bridge must land on the `txn ApplicationArgs 0` read.
    targets = [v for _, v in _bridge_edges(xtg, "appcall-arg")]
    assert targets, "no appcall-arg bridge created"
    assert any(
        xtg.op_of(v) == "txn"
        and xtg.immediates_of(v) == "ApplicationArgs 0"
        for v in targets
    ), "txn-form ApplicationArgs read was not bridged"
    # and the attacker arg reaches the callee Receiver across it.
    findings = cross_taint_findings(xtg)
    assert any(
        f.sink.app_id == 100 and f.sink_name == "itxn_field Receiver"
        for f in findings
    ), [f.sink_name for f in findings]


# --- (2) foreign-array channel: Accounts, offset +1 ----------------------

# Caller forwards arg0 as the inner txn's first foreign account.
_ACCT_CALLER = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field Accounts
itxn_submit
int 1
return
"""
# Callee reads `txn Accounts 1` (index 0 is the Sender) and pays it.  It ALSO
# reads `txn Accounts 0` (its Sender) into a no-op assert — that read must NOT
# receive the caller's forwarded-account bridge (offset proof).
_ACCT_CALLEE = """#pragma version 10
txn Accounts 0
len
assert
itxn_begin
txn Accounts 1
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def test_foreign_account_bridge_uses_offset_one(tmp_path):
    xtg = _build(tmp_path, _ACCT_CALLER, _ACCT_CALLEE)
    targets = [v for _, v in _bridge_edges(xtg, "appcall-foreign")]
    assert targets, "no appcall-foreign bridge created"
    imms = {xtg.immediates_of(v) for v in targets}
    # the caller's first pushed Accounts entry maps to callee read index 1...
    assert "Accounts 1" in imms, imms
    # ...and NOT to index 0 (the callee's Sender, an implicit entry).
    assert "Accounts 0" not in imms, "forwarded account wrongly bridged to Sender slot"


def test_foreign_account_taint_reaches_sink(tmp_path):
    xtg = _build(tmp_path, _ACCT_CALLER, _ACCT_CALLEE)
    findings = cross_taint_findings(xtg)
    f = [f for f in findings if f.sink_name == "itxn_field Receiver"]
    assert f, [x.sink_name for x in findings]
    assert f[0].source.app_id is None      # attacker arg enters at the caller
    assert f[0].sink.app_id == 100          # foreign account paid in the callee


# --- (2b) foreign-array channel: Assets, NO offset -----------------------

_ASSET_CALLER = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field Assets
itxn_submit
int 1
return
"""
# Assets has no implicit entry, so the caller's first pushed asset is read at
# index 0 (offset 0), unlike Accounts/Applications.
_ASSET_CALLEE = """#pragma version 10
itxn_begin
txn Assets 0
itxn_field AssetReceiver
int 1000
itxn_field AssetAmount
itxn_submit
int 1
return
"""


def test_foreign_asset_bridge_uses_offset_zero(tmp_path):
    xtg = _build(tmp_path, _ASSET_CALLER, _ASSET_CALLEE)
    targets = {xtg.immediates_of(v) for _, v in _bridge_edges(xtg, "appcall-foreign")}
    assert "Assets 0" in targets, targets   # no implicit-entry offset for Assets
