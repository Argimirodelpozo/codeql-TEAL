"""Transitive cross-contract pin propagation through a forwarding hop.

A -> B -> C, where A pins B's ApplicationArgs[0] to a constant and B FORWARDS that
arg verbatim to C (a proxy/forwarder). The pin must propagate through the
forwarding hop, so a value C draws from it is recognised as caller-fixed (not
attacker-controlled) and the callee finding is suppressed -- for BOTH the IR
(trusted_args) and SSA (seeded predicates) detectors. An arg that is forwarded but
NOT pinned at the root still surfaces.
"""
from tealql.tealtools.intercontract.analysis import XContractGraph
from tealql.security.xcontract import cross_detection_findings
from helpers import make_xcontract

_K = "0x0102030405060708091011121314151617181920212223242526272829303132"

# B forwards its ApplicationArgs[0] onward to C (app 200).
_B = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 200
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field ApplicationArgs
itxn_submit
int 1
return
"""

# C pays ApplicationArgs[0] as Receiver.
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

# A PINS B's ApplicationArgs[0] to a constant.
_A_PINNED = f"""#pragma version 10
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

# A forwards a NON-constant arg to B (no pin).
_A_UNPINNED = """#pragma version 10
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


def test_transitive_pin_suppresses_through_forwarding_hop(tmp_path):
    caller, registry = make_xcontract(tmp_path, _A_PINNED, {100: _B, 200: _C})
    g = XContractGraph.build(caller, registry)
    # the forwarding edge B->C carries the propagated pin
    bc = next(e for e in g.edges if e.caller_app_id == 100 and e.site.app_id == 200)
    assert bc.site.const_args == {0: _K}
    assert cross_detection_findings(g, detector_names=["tainted-fund-flow"]) == []
    assert cross_detection_findings(g, detector_names=["tainted-fund-flow"]) == []


def test_forwarded_but_unpinned_still_fires(tmp_path):
    caller, registry = make_xcontract(tmp_path, _A_UNPINNED, {100: _B, 200: _C})
    g = XContractGraph.build(caller, registry)
    bc = next(e for e in g.edges if e.caller_app_id == 100 and e.site.app_id == 200)
    assert bc.site.const_args == {}                       # nothing pinned to forward
    findings = cross_detection_findings(g, detector_names=["tainted-fund-flow"])
    assert [f.app_id for f in findings] == [200]
