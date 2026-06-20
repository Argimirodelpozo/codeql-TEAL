"""Cross-contract fund-flow: the SSA tainted-fund-flow detector run across an
appcall boundary, seeded with the caller's constant args.

A caller that forwards an attacker-influenceable value into a callee's payment
field surfaces a finding (attributed to the call site); a caller that PINS that
arg to a constant suppresses it (the callee's guard-by-pin is recognised via the
seed). Reuses detections.xcontract.cross_detection_findings + the seeded
PathPredicateAnalysis -- no new engine.
"""
from pathlib import Path

from tealtools.ssa import SSAProgram
from tealtools.xcontract import XContractGraph
from tealtools.detections.xcontract import cross_detection_findings

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

# caller appcalls app 555 forwarding NO constant args (attacker controls arg 0).
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

# caller PINS ApplicationArgs[0] to a constant address.
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


def _cross(caller_teal: str, tmp_path: Path):
    callee = tmp_path / "callee.teal"
    callee.write_text(_CALLEE)
    caller_p = tmp_path / "caller.teal"
    caller_p.write_text(caller_teal)
    caller = SSAProgram(str(caller_p), verbose=False)
    caller.propagate_constants()
    graph = XContractGraph.build(caller, {555: str(callee)})
    return graph, cross_detection_findings(graph, detector_names=["tainted-fund-flow"])


def test_forwarded_value_surfaces_cross_contract(tmp_path):
    graph, findings = _cross(_CALLER_FWD, tmp_path)
    assert [s.app_id for s in graph.sites] == [555]
    assert len(findings) == 1
    f = findings[0]
    assert f.app_id == 555
    assert f.detector_name == "sec-guide/tainted-fund-flow"
    assert "Receiver" in f.violation.pretty()


def test_caller_pinned_arg_suppresses(tmp_path):
    # The caller fixes ApplicationArgs[0] to a constant -> the callee's payment is
    # not attacker-controlled on THIS edge; the seed makes the guard recognised.
    graph, findings = _cross(_CALLER_PINNED, tmp_path)
    assert [s.app_id for s in graph.sites] == [555]
    assert findings == []
