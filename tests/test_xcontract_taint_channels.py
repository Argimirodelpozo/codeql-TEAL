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


_ARG_CALLEE_DYNAMIC = """#pragma version 10
itxn_begin
global GroupSize
txnas ApplicationArgs
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def test_arg_bridge_reaches_dynamic_index_read(tmp_path):
    xtg = _build(tmp_path, _ARG_CALLER, _ARG_CALLEE_DYNAMIC)
    targets = [v for _, v in _bridge_edges(xtg, "appcall-arg")]
    assert any(xtg.op_of(v) == "txnas"
               and xtg.immediates_of(v) == "ApplicationArgs" for v in targets)
    findings = cross_taint_findings(xtg)
    assert any(f.sink.app_id == 100 and f.sink_name == "itxn_field Receiver"
               for f in findings), [f.sink_name for f in findings]


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


# --- (3) return channel: the scalar `itxn LastLog` read form -------------

# Caller forwards arg0 to the callee, then reads the callee's single log return
# via the SCALAR `itxn LastLog` (not the `itxna Logs i` array form) and pays it.
_RET_CALLER = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field ApplicationArgs
itxn_submit
itxn LastLog
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
# Callee logs the attacker-derived arg — this is the return value the caller reads.
_RET_CALLEE = """#pragma version 10
txna ApplicationArgs 0
log
int 1
return
"""


# Same shape, reading the return via the `itxna Logs 0` array form instead.
_RET_CALLER_ARRAY = _RET_CALLER.replace("itxn LastLog", "itxna Logs 0")


# A callee that does NOT log — no return value, so no return channel at all.
_RET_CALLEE_NO_LOG = """#pragma version 10
int 1
return
"""


def test_return_bridge_reaches_lastlog_read(tmp_path):
    """A callee ``log`` must bridge to the caller's scalar ``itxn LastLog`` read,
    not only the ``itxna Logs i`` array form — before the fix the return-read
    filter accepted only first-immediate ``Logs`` and dropped ``LastLog``, so the
    bridge was silently absent and the detector's verdict flipped on which
    equivalent return opcode the caller used (parity with the group axis, see
    ``group_taint_graph._add_log_bridges``)."""
    xtg = _build(tmp_path, _RET_CALLER, _RET_CALLEE)
    lastlog = [v for _, v in _bridge_edges(xtg, "appcall-return")
               if xtg.op_of(v) == "itxn" and xtg.immediates_of(v) == "LastLog"]
    assert lastlog, "itxn LastLog return read was not bridged"
    # Parity: the array form is bridged identically (same single return edge).
    xtg_arr = _build(tmp_path, _RET_CALLER_ARRAY, _RET_CALLEE)
    arr = [v for _, v in _bridge_edges(xtg_arr, "appcall-return")]
    assert len(arr) == len(_bridge_edges(xtg, "appcall-return")), \
        "LastLog and Logs return reads must bridge symmetrically"


def test_return_channel_reaches_caller_sink(tmp_path):
    """End-to-end RETURN channel: attacker arg -> callee log -> caller reads the
    return (LastLog OR Logs) -> caller sink. This lands in the CALLER's scope but
    is genuinely cross-contract (the caller alone can't tell the inner-txn return
    carries attacker data), so it must be reported — for either return opcode."""
    for caller_src in (_RET_CALLER, _RET_CALLER_ARRAY):
        xtg = _build(tmp_path, caller_src, _RET_CALLEE)
        findings = cross_taint_findings(xtg)
        recv = [f for f in findings if f.sink_name == "itxn_field Receiver"]
        assert recv, f"return channel missed for {caller_src.splitlines()[9]!r}: " \
            f"{[f.sink_name for f in findings]}"
        # The witness must actually cross into the callee and come back.
        assert any(n.app_id is not None for n in recv[0].path), \
            "witness path does not cross the appcall boundary"
        assert recv[0].sink.app_id is None, "return-channel sink is in the caller"


def test_return_channel_needs_a_log(tmp_path):
    """No callee ``log`` -> no return value -> no return channel: the caller's
    ``itxn LastLog`` read is untied to attacker input, so nothing is reported."""
    xtg = _build(tmp_path, _RET_CALLER, _RET_CALLEE_NO_LOG)
    assert not [f for f in cross_taint_findings(xtg)
                if f.sink_name == "itxn_field Receiver"]
