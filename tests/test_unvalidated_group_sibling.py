"""sec-guide/unvalidated-group-sibling: trusting a sibling transfer it never pins.

The Algorand composition bug: an app reads a sibling transaction's value
(gtxn N Amount / AssetAmount) but never asserts that sibling's
Receiver/AssetReceiver == Global.CurrentApplicationAddress, so the payment the app
credits may go to someone else. Distinct from group-size-check (which only counts
transactions).
"""
from pathlib import Path

from tealtools.ssa import SSAProgram
from security import DETECTORS

_DET = DETECTORS["unvalidated-group-sibling"]


def _detect(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return _DET(SSAProgram(str(p), verbose=False)).detect()


def test_registered():
    assert "unvalidated-group-sibling" in DETECTORS
    assert "app" in getattr(_DET, "applies_to", frozenset())


_VULN = """#pragma version 10
    gtxn 0 Amount
    int 1000000
    >=
    assert
    int 1
    return
"""


def test_unpinned_payment_flagged(tmp_path):
    vs = _detect(_VULN, tmp_path)
    assert len(vs) == 1
    assert vs[0].index == 0
    assert vs[0].value_field == "Amount"
    assert vs[0].receiver_field == "Receiver"


_SAFE_PINNED = """#pragma version 10
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    assert
    gtxn 0 Amount
    int 1000000
    >=
    assert
    int 1
    return
"""


def test_pinned_receiver_clean(tmp_path):
    assert _detect(_SAFE_PINNED, tmp_path) == []


# The pin via a branch-to-reject (bz reject; ...; reject: err) instead of assert.
_SAFE_BRANCH = """#pragma version 10
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    bz reject
    gtxn 0 Amount
    int 1000000
    >=
    assert
    int 1
    return
reject:
    err
"""


def test_pinned_via_branch_clean(tmp_path):
    assert _detect(_SAFE_BRANCH, tmp_path) == []


# The pin lives inside a proto subroutine (frame_dig) — must still count.
_SAFE_SUB = """#pragma version 10
    gtxn 0 Receiver
    callsub check
    gtxn 0 Amount
    int 1000000
    >=
    assert
    int 1
    return
check:
    proto 1 0
    frame_dig -1
    global CurrentApplicationAddress
    ==
    assert
    retsub
"""


def test_pinned_in_subroutine_clean(tmp_path):
    assert _detect(_SAFE_SUB, tmp_path) == []


# Reads only the sibling's Sender (no value field) -> no transfer trusted.
_NO_VALUE = """#pragma version 10
    gtxn 0 Sender
    txn Sender
    ==
    assert
    int 1
    return
"""


def test_no_value_field_clean(tmp_path):
    assert _detect(_NO_VALUE, tmp_path) == []
