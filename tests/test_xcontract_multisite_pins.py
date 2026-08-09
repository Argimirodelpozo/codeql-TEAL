"""Cross-contract pins are INTERSECTED across every site that calls a shared
callee — a pin is honored only if all callers agree on the same constant.

Regression for the first-site-wins bug: the callee was seeded-analysed once with
the FIRST site's pins, so a second site leaving the same arg attacker-controlled
inherited the (over-pinned) analysis and its exploitable flow was suppressed.
"""
from tealql.tealtools.intercontract.analysis import XContractGraph
from tealql.security.xcontract import cross_detection_findings
from helpers import make_xcontract

_K = "0x0102030405060708091011121314151617181920212223242526272829303132"

# Callee (app 100): pays ApplicationArgs[0] straight to Receiver.
_C = """#pragma version 10
itxn_begin
txna ApplicationArgs 0
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""

# Caller calls app 100 TWICE: site 1 PINS arg0 to a const; site 2 forwards an
# ATTACKER-controlled arg0 (unpinned). The first (pinned) site must NOT suppress
# the second site's flow.
_CALLER_PINNED_THEN_UNPINNED = f"""#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
byte {_K}
itxn_field ApplicationArgs
itxn_submit
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

# Both sites pin arg0 to the SAME const -> the pin still holds, flow suppressed.
_CALLER_BOTH_PINNED = f"""#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
byte {_K}
itxn_field ApplicationArgs
itxn_submit
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
byte {_K}
itxn_field ApplicationArgs
itxn_submit
int 1
return
"""


def test_disagreeing_sites_do_not_suppress(tmp_path):
    # one site pins arg0, the other leaves it attacker-controlled: the
    # intersection drops the pin, so the callee's arg0->Receiver flow FIRES.
    caller, registry = make_xcontract(tmp_path, _CALLER_PINNED_THEN_UNPINNED, {100: _C})
    g = XContractGraph.build(caller, registry)
    for det in ("ir-tainted-fund-flow", "tainted-fund-flow"):
        findings = cross_detection_findings(g, detector_names=[det])
        assert [f.app_id for f in findings] == [100], det


def test_all_sites_agree_still_suppresses(tmp_path):
    # every site pins arg0 to the same const -> the pin holds, flow suppressed.
    caller, registry = make_xcontract(tmp_path, _CALLER_BOTH_PINNED, {100: _C})
    g = XContractGraph.build(caller, registry)
    assert cross_detection_findings(g, detector_names=["ir-tainted-fund-flow"]) == []
    assert cross_detection_findings(g, detector_names=["tainted-fund-flow"]) == []
