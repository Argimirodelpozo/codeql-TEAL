"""Multi-hop cross-contract taint: the unified taint graph chains its appcall
bridges transitively (A -> B -> C), so an attacker arg in A reaching a sink in
C *two hops deep* surfaces — it flows over the chained appcall-arg bridges, no
special-case forwarding.
"""
from helpers import make_xcontract
from tealql.tealtools.dataflow.xcontract_taint_graph import (
    XContractTaintGraph, cross_taint_findings,
)

# A forwards its arg 0 to B's appcall; B forwards ITS arg 0 to C's appcall;
# C pays an attacker-controlled Receiver with that arg.
_FWD = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int {app}
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field ApplicationArgs
itxn_submit
int 1
return
"""
_SINK = """#pragma version 10
itxn_begin
txna ApplicationArgs 0
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def _build(tmp_path, **kw):
    caller, registry = make_xcontract(
        tmp_path, _FWD.format(app=100),
        {100: _FWD.format(app=200), 200: _SINK})
    return XContractTaintGraph.build(caller, registry, **kw)


def test_graph_spans_all_hops(tmp_path):
    xtg = _build(tmp_path)
    app_ids = {n.app_id for n in xtg.nodes() if n.app_id is not None}
    assert app_ids == {100, 200}          # B (1 hop) and C (2 hops)


def test_bridges_chain_across_hops(tmp_path):
    xtg = _build(tmp_path)
    # an appcall-arg bridge exists FROM the intermediate B's scope (app 100)
    # into C's scope (app 200), not just from the root.
    bridged = {
        (u.app_id, v.app_id)
        for u, v, data in xtg.g.edges(data=True)
        if "appcall-arg" in data.get("kinds", ())
    }
    assert (None, 100) in bridged         # root A -> B
    assert (100, 200) in bridged          # B -> C


def test_attacker_arg_reaches_two_hop_sink(tmp_path):
    xtg = _build(tmp_path)
    findings = cross_taint_findings(xtg)
    # exactly the A-arg -> C-Receiver flow, across A -> B -> C.
    assert len(findings) == 1
    f = findings[0]
    assert f.source.app_id is None                 # attacker input enters at A
    assert f.sink.app_id == 200                     # sink lives in C
    assert f.sink_name == "itxn_field Receiver"


def test_depth_cap_stops_before_c(tmp_path):
    # max_depth=1: only B is graphed; C (2 hops) is absent -> no finding.
    xtg = _build(tmp_path, max_depth=1)
    assert {n.app_id for n in xtg.nodes() if n.app_id is not None} == {100}
    assert cross_taint_findings(xtg) == []
