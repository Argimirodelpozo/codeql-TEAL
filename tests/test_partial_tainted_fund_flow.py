"""sec-guide/partial-tainted-fund-flow: byte-precise fund-flow (validation bypass).

Closes the slot-granular blind spot of tainted-fund-flow: a contract that
validates ONE sub-field of an argument (a selector / length prefix) but lets a
DIFFERENT, unchecked sub-field (an embedded address / amount) steer an inner
payment. Built on the byte-interval taint engine (validation-narrowing); reports
only the net-new findings the boolean detector misses.
"""
from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.security import DETECTORS

_PARTIAL = DETECTORS["partial-tainted-fund-flow"]
_TFF = DETECTORS["tainted-fund-flow"]


def _detect(det, teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return det(SSAProgram(str(p))).detect()


def test_registered():
    assert "partial-tainted-fund-flow" in DETECTORS
    assert "app" in getattr(_PARTIAL, "applies_to", frozenset())


# Validate arg[0:2] (a selector), pay arg[2:34] (an embedded address) to Receiver.
# The slot-granular detector sees "the arg was checked" and suppresses; the
# byte-precise detector sees the funds bytes [2:34] were never validated.
_PARTIAL_BYPASS = """#pragma version 10
    txna ApplicationArgs 0
    int 0
    extract_uint16
    int 1
    ==
    assert
    itxn_begin
    int pay
    itxn_field TypeEnum
    txna ApplicationArgs 0
    extract 2 32
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_partial_validation_bypass_flagged(tmp_path):
    # tainted-fund-flow MISSES it (slot-granular guard over-suppresses)...
    assert _detect(_TFF, _PARTIAL_BYPASS, tmp_path) == []
    # ...the byte-precise detector recovers it.
    vs = _detect(_PARTIAL, _PARTIAL_BYPASS, tmp_path)
    assert len(vs) == 1
    assert vs[0].field == "Receiver"
    assert "32 bytes" in vs[0].message  # address-sized window recognised


# Validate the EXACT bytes [2:34] that flow to Receiver -> narrowing clears them.
_EXACT_VALIDATED = """#pragma version 10
    txna ApplicationArgs 0
    extract 2 32
    addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
    ==
    assert
    itxn_begin
    int pay
    itxn_field TypeEnum
    txna ApplicationArgs 0
    extract 2 32
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_exact_bytes_validated_clean(tmp_path):
    assert _detect(_PARTIAL, _EXACT_VALIDATED, tmp_path) == []


# A plain whole-value flow is owned by tainted-fund-flow; partial subtracts it.
_WHOLE_VALUE = """#pragma version 10
    itxn_begin
    int pay
    itxn_field TypeEnum
    txna ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_whole_value_left_to_tff(tmp_path):
    assert _detect(_TFF, _WHOLE_VALUE, tmp_path)            # tff owns it
    assert _detect(_PARTIAL, _WHOLE_VALUE, tmp_path) == []  # partial defers
