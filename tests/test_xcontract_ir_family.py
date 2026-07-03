"""Cross-contract for the IR taint-to-sink family (appcall + asset), same as the
fund-flow case: the detector runs on the discovered callee, a forwarded
attacker-controlled value surfaces, and a caller-pinned arg suppresses it (via
the call site's const_args -> trusted_args -> IR taint).
"""
import pytest

from tealql.tealtools.xcontract import XContractGraph
from tealql.security.xcontract import cross_detection_findings
from helpers import make_xcontract

# callee: the attacker picks the inner-appcall target (ApplicationID).
_CALLEE_APPCALL = """#pragma version 10
    itxn_begin
    int appl
    itxn_field TypeEnum
    txna ApplicationArgs 0
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# callee: the attacker picks WHICH asset moves (XferAsset), to a FIXED other party
# (so the receiver-context suppression doesn't apply).
_CALLEE_ASSET = """#pragma version 10
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 0
    btoi
    itxn_field XferAsset
    byte 0x0102030405060708091011121314151617181920212223242526272829303132
    itxn_field AssetReceiver
    int 1
    itxn_field AssetAmount
    itxn_submit
    int 1
    return
"""

_FWD = """#pragma version 10
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

_PINNED = """#pragma version 10
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    byte 0x01
    itxn_field ApplicationArgs
    itxn_submit
    int 1
    return
"""

_CASES = [
    ("ir-arbitrary-inner-appcall", _CALLEE_APPCALL),
    ("ir-arbitrary-inner-asset", _CALLEE_ASSET),
]


@pytest.mark.parametrize("detector,callee", _CASES)
def test_forwarded_value_surfaces(detector, callee, tmp_path):
    caller, registry = make_xcontract(tmp_path, _FWD, {555: callee})
    graph = XContractGraph.build(caller, registry)
    findings = cross_detection_findings(graph, detector_names=[detector])
    assert len(findings) == 1
    assert findings[0].app_id == 555


@pytest.mark.parametrize("detector,callee", _CASES)
def test_caller_pinned_arg_suppresses(detector, callee, tmp_path):
    caller, registry = make_xcontract(tmp_path, _PINNED, {555: callee})
    graph = XContractGraph.build(caller, registry)
    assert cross_detection_findings(graph, detector_names=[detector]) == []
