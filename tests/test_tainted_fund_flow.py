"""SSA-layer tainted-fund-flow detection (security/detections/tainted-fund-flow).

A user-input-tainted itxn payment field (Receiver / AssetReceiver / Amount /
AssetAmount) not dominated by a check of that value or the txn Sender. Reuses
PathPredicateAnalysis (dominance, interprocedural for free) + the existing SSA
taint/flow helpers.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.security import DETECTORS

_DET = DETECTORS["tainted-fund-flow"]


def _detect(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return _DET(SSAProgram(str(p))).detect()


def test_registered():
    assert "tainted-fund-flow" in DETECTORS
    assert "app" in getattr(_DET, "applies_to", frozenset())


_UNGUARDED = """#pragma version 10
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_unguarded_flagged(tmp_path):
    vs = _detect(_UNGUARDED, tmp_path)
    fields = {v.field for v in vs}
    assert "Receiver" in fields
    assert all(v.severity in ("HIGH", "MEDIUM") for v in vs)


_SENDER = """#pragma version 10
    txn Sender
    global CreatorAddress
    ==
    assert
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    itxn_submit
    int 1
    return
"""


def test_sender_guard_clears(tmp_path):
    assert _detect(_SENDER, tmp_path) == []


# `Sender != ZeroAddress` is a SANITY check, not authentication — it pins no
# identity, so it must NOT clear a tainted fund flow (was a false negative: any
# comparison touching Sender counted as a guard, ignoring op and polarity).
_SENDER_SANITY = """#pragma version 10
    txn Sender
    global ZeroAddress
    !=
    assert
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    itxn_submit
    int 1
    return
"""


def test_sender_sanity_check_does_not_clear(tmp_path):
    vs = _detect(_SENDER_SANITY, tmp_path)
    assert any(v.field == "Receiver" for v in vs)


@pytest.mark.parametrize("identity", [
    "txn ApplicationArgs 1",
    "gtxn 1 Sender",
    "byte 0x0102",
])
def test_attacker_or_invalid_sender_identity_does_not_clear(identity, tmp_path):
    teal = f"""#pragma version 10
txn Sender
{identity}
==
assert
itxn_begin
txn ApplicationArgs 0
itxn_field Receiver
itxn_submit
int 1
return
"""
    assert any(v.field == "Receiver" for v in _detect(teal, tmp_path))


def test_creator_comparison_without_sender_does_not_clear(tmp_path):
    teal = """#pragma version 10
global CreatorAddress
txn ApplicationArgs 1
==
assert
itxn_begin
txn ApplicationArgs 0
itxn_field Receiver
itxn_submit
int 1
return
"""
    assert any(v.field == "Receiver" for v in _detect(teal, tmp_path))


def test_negated_sender_inequality_clears(tmp_path):
    teal = _SENDER.replace("==\n", "!=\n    !\n")
    assert _detect(teal, tmp_path) == []


_VALCHECK = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    int 100
    <=
    assert
    itxn_begin
    txn ApplicationArgs 0
    btoi
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_value_check_same_slot_clears(tmp_path):
    # The amount<=100 assert tests the same ApplicationArgs[0] slot the sink uses
    # (taint propagates through btoi), so it's guarded.
    assert _detect(_VALCHECK, tmp_path) == []


@pytest.mark.parametrize("guard", [
    "txn ApplicationArgs 0\nlen\nint 8\n==\nassert",
    "txn ApplicationArgs 0\nbtoi\nint 1\n||\nassert",
    "txn ApplicationArgs 0\ndup\n==\nassert",
    "txn ApplicationArgs 0\nbtoi\nint 1\n%\nint 0\n==\nassert",
])
def test_vacuous_input_predicate_does_not_clear(guard, tmp_path):
    teal = f"""#pragma version 10
{guard}
itxn_begin
txn ApplicationArgs 0
itxn_field Receiver
itxn_submit
int 1
return
"""
    vs = _detect(teal, tmp_path)
    assert any(v.field == "Receiver" for v in vs)


_BRANCH = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    int 5
    >
    bz reject
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    itxn_submit
    int 1
    return
reject:
    int 0
    return
"""


def test_branch_guard_clears(tmp_path):
    # Cross-block dominance: the bz forces arg0>5 on the path to the itxn.
    assert _detect(_BRANCH, tmp_path) == []


_CONSTANT = """#pragma version 10
    itxn_begin
    global CurrentApplicationAddress
    itxn_field Receiver
    int 1
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_constant_receiver_not_flagged(tmp_path):
    # A non-user-input (constant) receiver is not attacker-controlled.
    assert _detect(_CONSTANT, tmp_path) == []


# A tainted value passed INTO a subroutine as a parameter and paid out inside the
# callee. The base SSA def-use leaves frame_dig disconnected, but the taint now
# crosses it natively via the frame_flow caller-arg -> callee-param edges.
_PARAM_FED = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    callsub pay
    int 1
    return
pay:
    proto 1 0
    itxn_begin
    frame_dig -1
    itxn_field Amount
    itxn_submit
    retsub
"""


def test_param_fed_caught_interprocedurally(tmp_path):
    # The formerly-known FN: the value fed into the `pay` sub's param is now
    # tainted at the in-callee sink natively, via the frame_flow caller-arg ->
    # callee-param edges (no IR lift). One MEDIUM Amount finding.
    findings = _detect(_PARAM_FED, tmp_path)
    assert len(findings) == 1, [f.pretty() for f in findings]
    assert findings[0].field == "Amount"
