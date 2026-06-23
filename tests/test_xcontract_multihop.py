"""Multi-hop cross-contract analysis: ``XContractGraph.build`` walks appcall
sites transitively (A -> B -> C -> ...), not just one hop.

The headline property: a detector finding inside a contract reached only via a
CHAIN of appcalls still surfaces, because ``callees`` / ``analyses`` span every
hop. Also covers the call-graph structure (``edges`` / ``chains``), the depth
cap, and cycle safety.
"""
from tealtools.xcontract import XContractGraph
from tealtools.detections.xcontract import cross_detection_findings
from helpers import make_xcontract

# A -> appcall app 100 (B); B -> appcall app 200 (C); C pays an
# attacker-controlled Receiver with no guard (tainted-fund-flow fires).
_A = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
itxn_submit
int 1
return
"""
_B = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 200
itxn_field ApplicationID
itxn_submit
int 1
return
"""
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


def _chain(tmp_path, *, c_calls_back: bool = False):
    # optional cycle: C calls back to app 100 (B)
    c_src = _C if not c_calls_back else _C.replace(
        "itxn_submit\nint 1\nreturn",
        "itxn_submit\nitxn_begin\nint 6\nitxn_field TypeEnum\n"
        "int 100\nitxn_field ApplicationID\nitxn_submit\nint 1\nreturn",
    )
    return make_xcontract(tmp_path, _A, {100: _B, 200: c_src})


def test_callees_span_all_hops(tmp_path):
    caller, registry = _chain(tmp_path)
    g = XContractGraph.build(caller, registry)
    # B (one hop) AND C (two hops) are both loaded + analysed.
    assert sorted(g.callees) == [100, 200]
    assert sorted(g.analyses) == [100, 200]
    # `sites` stays the ROOT caller's only (backward compatible).
    assert [s.app_id for s in g.sites] == [100]


def test_edges_and_chains(tmp_path):
    caller, registry = _chain(tmp_path)
    g = XContractGraph.build(caller, registry)
    edges = {(e.caller_app_id, e.site.app_id, e.depth) for e in g.edges}
    assert (None, 100, 0) in edges      # root -> B
    assert (100, 200, 1) in edges       # B -> C
    assert g.chains() == [[100, 200]]


def test_finding_two_hops_deep_surfaces(tmp_path):
    caller, registry = _chain(tmp_path)
    g = XContractGraph.build(caller, registry)
    findings = cross_detection_findings(g, detector_names=["tainted-fund-flow"])
    # the unguarded payment lives in C, reached only A -> B -> C.
    assert len(findings) == 1
    assert findings[0].app_id == 200


def test_depth_cap_stops_the_walk(tmp_path):
    caller, registry = _chain(tmp_path)
    # max_depth=1: only the root's direct callees (B); C is NOT reached.
    g = XContractGraph.build(caller, registry, max_depth=1)
    assert sorted(g.callees) == [100]
    assert cross_detection_findings(g, detector_names=["tainted-fund-flow"]) == []


def test_cycle_terminates(tmp_path):
    # C calls back into B (app 100) -> a cycle. Build must terminate and still
    # analyse each contract once.
    caller, registry = _chain(tmp_path, c_calls_back=True)
    g = XContractGraph.build(caller, registry)
    assert sorted(g.callees) == [100, 200]
    # the back-edge C -> B is recorded but B is not re-analysed.
    assert (200, 100, 2) in {(e.caller_app_id, e.site.app_id, e.depth) for e in g.edges}
