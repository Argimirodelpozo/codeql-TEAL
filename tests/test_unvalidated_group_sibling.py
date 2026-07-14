"""sec-guide/unvalidated-group-sibling: trusting a sibling transfer it never pins.

The Algorand composition bug: an app reads a sibling transaction's value
(gtxn N Amount / AssetAmount) but never asserts that sibling's
Receiver/AssetReceiver == Global.CurrentApplicationAddress, so the payment the app
credits may go to someone else. Distinct from group-size-check (which only counts
transactions).
"""
from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.security import DETECTORS

_DET = DETECTORS["unvalidated-group-sibling"]


def _detect(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return _DET(SSAProgram(str(p))).detect()


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


# --- per-arm path-existence (the cross-arm false negative) -------------------

# An inline router: the `safe` arm pins gtxn 0 Receiver, the `vuln` arm reads
# gtxn 0 Amount with no pin. The old whole-program existence check let the safe
# arm's pin vouch for the vuln arm (0 findings). Path-existence flags the vuln arm.
_ROUTER_ONE_ARM_UNPINNED = """#pragma version 10
    txna ApplicationArgs 0
    byte "safe"
    ==
    bnz safe_path
    byte "vuln"
    ==
    bnz vuln_path
    err
safe_path:
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    assert
    gtxn 0 Amount
    pop
    int 1
    return
vuln_path:
    gtxn 0 Amount
    pop
    int 1
    return
"""


def test_router_unpinned_arm_flagged(tmp_path):
    vs = _detect(_ROUTER_ONE_ARM_UNPINNED, tmp_path)
    assert len(vs) == 1
    assert vs[0].index == 0 and vs[0].value_field == "Amount"
    assert "can approve" in vs[0].pretty()   # the per-arm (not "never pins") message


# Both arms pin the receiver -> every approving path is gated -> clean.
_ROUTER_BOTH_ARMS_PINNED = """#pragma version 10
    txna ApplicationArgs 0
    byte "a"
    ==
    bnz arm_a
    byte "b"
    ==
    bnz arm_b
    err
arm_a:
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    assert
    gtxn 0 Amount
    pop
    int 1
    return
arm_b:
    int 100
    pop
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    assert
    gtxn 0 Amount
    pop
    int 1
    return
"""


def test_router_both_arms_pinned_clean(tmp_path):
    assert _detect(_ROUTER_BOTH_ARMS_PINNED, tmp_path) == []


# --- scratch round-trip pin (the pre-existing enforcement false positive) ----

_SAFE_SCRATCH = """#pragma version 10
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    store 0
    load 0
    assert
    gtxn 0 Amount
    pop
    int 1
    return
"""


def test_pinned_via_scratch_clean(tmp_path):
    # the pin comparison is round-tripped through scratch before its assert; the
    # scratch-aware enforcement walk must still see it enforced.
    assert _detect(_SAFE_SCRATCH, tmp_path) == []


# A scratch slot holding the pin is CLOBBERED by a constant before the load —
# the assert enforces the constant, not the pin. Must-semantics keeps this flagged.
_VULN_SCRATCH_CLOBBERED = """#pragma version 10
    gtxn 0 Receiver
    global CurrentApplicationAddress
    ==
    store 0
    int 1
    store 0
    load 0
    assert
    gtxn 0 Amount
    pop
    int 1
    return
"""


def test_clobbered_scratch_pin_flagged(tmp_path):
    vs = _detect(_VULN_SCRATCH_CLOBBERED, tmp_path)
    assert len(vs) == 1 and vs[0].value_field == "Amount"


# --- type-precision suppression (the pre-existing axfer/Amount premise bug) ---

# Reads gtxn 1 Amount but pins gtxn 1 AssetReceiver -> the sibling is an axfer, so
# its ALGO Amount is definitionally 0 (inert). Not a trusted payment.
_SAFE_COMPLEMENT_TYPE = """#pragma version 10
    gtxn 1 AssetReceiver
    global CurrentApplicationAddress
    ==
    assert
    gtxn 1 Amount
    pop
    int 1
    return
"""


def test_complementary_receiver_pin_excludes_field(tmp_path):
    assert _detect(_SAFE_COMPLEMENT_TYPE, tmp_path) == []


# Reads gtxn 1 Amount and pins gtxn 1 TypeEnum == axfer -> inert Amount.
_SAFE_TYPEENUM = """#pragma version 10
    gtxn 1 TypeEnum
    int axfer
    ==
    assert
    gtxn 1 Amount
    pop
    int 1
    return
"""


def test_typeenum_exclusion_clean(tmp_path):
    assert _detect(_SAFE_TYPEENUM, tmp_path) == []


# ...but pinning the CARRYING type (pay for Amount) with no receiver pin is the
# real vuln — the type is right, the receiver is unchecked.
_VULN_CARRYING_TYPE = """#pragma version 10
    gtxn 1 TypeEnum
    int pay
    ==
    assert
    gtxn 1 Amount
    pop
    int 1
    return
"""


def test_carrying_type_still_flagged(tmp_path):
    vs = _detect(_VULN_CARRYING_TYPE, tmp_path)
    assert len(vs) == 1 and vs[0].value_field == "Amount"
