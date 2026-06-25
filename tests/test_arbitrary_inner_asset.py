"""sec-guide/arbitrary-inner-asset: attacker-controlled inner asset-transfer target.

A user-input-tainted itxn XferAsset (which ASA leaves the app) with no pin and not
returned to the caller -- the Tinyman-class asset-confusion shape. Mirrors
arbitrary-inner-appcall (the call-target detector) for the asset selector, with a
self-receiver suppression for the legit "withdraw the asset I name to myself" case.
"""
from pathlib import Path

from tealtools.ssa import SSAProgram
from security import DETECTORS

_DET = DETECTORS["arbitrary-inner-asset"]


def _detect(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    return _DET(SSAProgram(str(p), verbose=False)).detect()


def test_registered():
    assert "arbitrary-inner-asset" in DETECTORS
    assert "app" in getattr(_DET, "applies_to", frozenset())


_VULN = """#pragma version 10
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field XferAsset
    addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5HFFY
    itxn_field AssetReceiver
    int 1000
    itxn_field AssetAmount
    itxn_submit
    int 1
    return
"""


def test_tainted_asset_to_third_party_flagged(tmp_path):
    vs = _detect(_VULN, tmp_path)
    assert len(vs) == 1
    assert vs[0].field == "XferAsset"
    assert vs[0].severity == "HIGH"


# The legit "withdraw the asset I name back to myself" pattern: AssetReceiver is
# the sender, so the chooser can only receive their own chosen asset.
_SELF = """#pragma version 10
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field XferAsset
    txn Sender
    itxn_field AssetReceiver
    txna ApplicationArgs 2
    btoi
    itxn_field AssetAmount
    itxn_submit
    int 1
    return
"""


def test_withdraw_to_self_clean(tmp_path):
    assert _detect(_SELF, tmp_path) == []


_PINNED = """#pragma version 10
    txna ApplicationArgs 1
    btoi
    int 31566704
    ==
    assert
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field XferAsset
    addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5HFFY
    itxn_field AssetReceiver
    int 1000
    itxn_field AssetAmount
    itxn_submit
    int 1
    return
"""


def test_pinned_asset_clean(tmp_path):
    assert _detect(_PINNED, tmp_path) == []
