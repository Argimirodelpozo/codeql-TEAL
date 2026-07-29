"""Atomic-group cross-program taint via shared scratch
(:mod:`tealql.tealtools.dataflow.group_taint_graph`).

A value an earlier group member stashes in scratch (``store N``) flows into a
later member that reads it (``gload i N``), crossing the trust boundary WITHIN
one atomic group. The AVM rule ``i < k`` (only an earlier sibling) is enforced.
"""

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.dataflow.group_taint_graph import (
    GroupTaintGraph, group_taint_findings,
)

# member 0: stash attacker arg 0 into scratch slot 3.
_STASH = """#pragma version 8
txna ApplicationArgs 0
store 3
int 1
return
"""
# member 1: gload txn 0's slot 3 and pay it to an attacker-chosen Receiver.
_DRAIN = """#pragma version 8
gload 0 3
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def _build(tmp_path, srcs):
    progs = []
    for i, src in enumerate(srcs):
        p = tmp_path / f"m{i}.teal"
        p.write_text(src)
        prog = SSAProgram(str(p))
        prog.propagate_constants()
        progs.append(prog)
    return GroupTaintGraph.build(progs)


def test_graph_spans_all_members(tmp_path):
    gtg = _build(tmp_path, [_STASH, _DRAIN])
    indices = {gn.index for gn in gtg.nodes()}
    assert indices == {0, 1}


def test_store_gload_bridge_present(tmp_path):
    gtg = _build(tmp_path, [_STASH, _DRAIN])
    bridges = [
        (u, v) for u, v, d in gtg.g.edges(data=True) if "gload" in d.get("kinds", ())
    ]
    assert bridges, "no store->gload bridge"
    # the bridge goes from member 0's store to member 1's gload.
    u, v = bridges[0]
    assert u.index == 0 and gtg.op_of(u) == "store"
    assert v.index == 1 and gtg.op_of(v) == "gload"


def test_cross_group_taint_reaches_sink(tmp_path):
    gtg = _build(tmp_path, [_STASH, _DRAIN])
    findings = group_taint_findings(gtg)
    assert len(findings) == 1, [f.pretty() for f in findings]
    f = findings[0]
    assert f.source.index == 0                  # attacker arg enters at member 0
    assert f.sink.index == 1                     # paid out in member 1
    assert f.sink_name == "itxn_field Receiver"
    # the witness path actually crosses the member boundary.
    assert {n.index for n in f.path} == {0, 1}


def test_forward_gload_not_bridged(tmp_path):
    # member 0 gload's txn 1 (a LATER sibling) — AVM-invalid (i >= k); the bridge
    # must NOT be created, so nothing flows and there's no finding.
    fwd = """#pragma version 8
gload 1 3
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
    gtg = _build(tmp_path, [fwd, _STASH])
    bridges = [d for _, _, d in gtg.g.edges(data=True) if "gload" in d.get("kinds", ())]
    assert bridges == []
    assert group_taint_findings(gtg) == []


def test_log_channel_cross_group(tmp_path):
    # member 0 logs the attacker arg; member 1 reads `gtxn 0 LastLog` and pays it.
    log_member = """#pragma version 8
txna ApplicationArgs 0
log
int 1
return
"""
    read_log = """#pragma version 8
gtxn 0 LastLog
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
    gtg = _build(tmp_path, [log_member, read_log])
    kinds = {kk for _, _, d in gtg.g.edges(data=True) for kk in d.get("kinds", ())}
    assert "log" in kinds, "no log->gtxn bridge"
    findings = group_taint_findings(gtg)
    assert any(f.source.index == 0 and f.sink.index == 1
               and f.sink_name == "itxn_field Receiver" for f in findings), \
        [f.pretty() for f in findings]


def test_dynamic_gloads_conservatively_bridged(tmp_path):
    # member 1 uses `gloads 3` (sibling index from the stack) — we can't pin the
    # index, so member 0's `store 3` is conservatively bridged and taint flows.
    drain_gloads = """#pragma version 8
int 0
gloads 3
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
    gtg = _build(tmp_path, [_STASH, drain_gloads])
    findings = group_taint_findings(gtg)
    assert any(f.source.index == 0 and f.sink.index == 1 for f in findings), \
        [f.pretty() for f in findings]


def test_no_gload_means_no_cross_member_flow(tmp_path):
    # two members that DON'T share scratch — no cross-group finding.
    standalone = """#pragma version 8
txna ApplicationArgs 0
itxn_begin
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
    gtg = _build(tmp_path, [_STASH, standalone])
    assert group_taint_findings(gtg) == []
