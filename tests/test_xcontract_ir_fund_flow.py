"""Cross-contract fund-flow on the IR-layer detector: the IR ir-tainted-fund-flow
run across an appcall boundary, with the caller's pinned args suppressing the
callee finding.

Mirrors test_xcontract_fund_flow (the SSA detector) -- the IR detector now covers
the same cross-contract case (run on the discovered callee; suppress when the
caller pins the callee's input), so it subsumes the SSA detector's cross-contract
strength. The mechanism: detections.xcontract._construct_detector passes the call
site's const_args as ``trusted_args``, which the IR taint excludes from its
user-input source set.
"""
from tealql.tealtools.xcontract import XContractGraph
from tealql.security.xcontract import cross_detection_findings
from helpers import make_xcontract

# callee pays an attacker-controlled Receiver (the arg the caller passes).
_CALLEE = """#pragma version 10
    itxn_begin
    txna ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""

_CALLER_FWD = """#pragma version 10
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

_CALLER_PINNED = """#pragma version 10
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    byte 0x0000000000000000000000000000000000000000000000000000000000000000
    itxn_field ApplicationArgs
    itxn_submit
    int 1
    return
"""


def _cross(caller_teal, tmp_path):
    caller, registry = make_xcontract(tmp_path, caller_teal, {555: _CALLEE})
    graph = XContractGraph.build(caller, registry)
    return graph, cross_detection_findings(
        graph, detector_names=["ir-tainted-fund-flow"])


def test_forwarded_value_surfaces_cross_contract(tmp_path):
    graph, findings = _cross(_CALLER_FWD, tmp_path)
    assert [s.app_id for s in graph.sites] == [555]
    assert len(findings) == 1
    f = findings[0]
    assert f.app_id == 555
    assert f.detector_name == "sec-guide/ir-tainted-fund-flow"
    assert "Receiver" in f.violation.pretty()


def test_caller_pinned_arg_suppresses(tmp_path):
    # caller fixes ApplicationArgs[0] -> the IR taint excludes that index (passed
    # as trusted_args), so the callee payment isn't attacker-controlled here.
    graph, findings = _cross(_CALLER_PINNED, tmp_path)
    assert [s.app_id for s in graph.sites] == [555]
    assert findings == []
