"""sec-guide/arbitrary-inner-appcall: attacker-controlled inner-app-call target.

A user-input-tainted ``itxn_field ApplicationID`` (the app this contract calls)
with no dominating check of the target or txn Sender — a confused-deputy. Shares
the taint + guard machinery with tainted-fund-flow (security.common), so the tests
here focus on the call-target field and the suppression shapes (constant target,
pinned target, sender-gated).
"""
from pathlib import Path

from tealtools.ssa import SSAProgram
from security import DETECTORS

_DET = DETECTORS["arbitrary-inner-appcall"]


def _detect(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return _DET(SSAProgram(str(p))).detect()


def test_registered():
    assert "arbitrary-inner-appcall" in DETECTORS
    assert "app" in getattr(_DET, "applies_to", frozenset())


_VULN = """#pragma version 10
    itxn_begin
    int appl
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_unguarded_target_flagged(tmp_path):
    vs = _detect(_VULN, tmp_path)
    assert len(vs) == 1
    assert vs[0].field == "ApplicationID"
    assert vs[0].severity == "HIGH"


_SAFE_CONST = """#pragma version 10
    itxn_begin
    int appl
    itxn_field TypeEnum
    int 12345
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_constant_target_clean(tmp_path):
    assert _detect(_SAFE_CONST, tmp_path) == []


_SAFE_PINNED = """#pragma version 10
    txna ApplicationArgs 1
    btoi
    int 999
    ==
    assert
    itxn_begin
    int appl
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_pinned_target_clean(tmp_path):
    assert _detect(_SAFE_PINNED, tmp_path) == []


_SAFE_SENDER = """#pragma version 10
    txn Sender
    global CreatorAddress
    ==
    assert
    itxn_begin
    int appl
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_sender_gated_clean(tmp_path):
    assert _detect(_SAFE_SENDER, tmp_path) == []
