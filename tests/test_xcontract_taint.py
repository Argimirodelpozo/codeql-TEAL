"""Integration test for the cross-contract taint graph
(``tealql.tealtools.dataflow.xcontract_taint_graph``).

Builds the ``arg_to_callee_sink`` fixture's merged caller+callee graph
and checks that (a) all three appcall bridges are created and (b) the
reachability detector follows an attacker arg from the caller, across
the forward-arg bridge, to a sensitive payment sink in the callee.

Requires the fixtures (built on demand by conftest); skips cleanly
if CodeQL isn't available in this environment.
"""
from pathlib import Path

import pytest

FIXTURE = (
    Path(__file__).resolve().parent
    / "tealtools/xcontract_taint/arg_to_callee_sink"
)


@pytest.fixture(scope="module")
def xtg():
    if not (FIXTURE / "caller").exists() or not (FIXTURE / "callee").exists():
        pytest.skip("fixture DBs not present (CodeQL unavailable?)")
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.dataflow.xcontract_taint_graph import XContractTaintGraph
    from tealql.tealtools.intercontract.analysis import load_registry

    reg = load_registry(FIXTURE / "registry.yml")
    try:
        caller = SSAProgram(str(FIXTURE / "caller"))
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")
    return XContractTaintGraph.build(caller, reg)


def _edge_kinds(xtg) -> set:
    out: set = set()
    for _, _, data in xtg.g.edges(data=True):
        out |= set(data.get("kinds", ()))
    return out


class TestBridges:
    def test_all_three_appcall_bridges_present(self, xtg):
        kinds = _edge_kinds(xtg)
        assert "appcall-arg" in kinds, "forward arg bridge missing"
        assert "appcall-sender" in kinds, "sender bridge missing"
        assert "appcall-return" in kinds, "return bridge missing"

    def test_sender_bridge_targets_callee_sender_read(self, xtg):
        # The sentinel caller-app-addr node feeds the callee's txn Sender.
        sender_reads = xtg.find(op="txn", immediates="Sender")
        assert sender_reads, "callee txn Sender node missing"
        for sr in sender_reads:
            preds = list(xtg.g.predecessors(sr))
            assert any(
                "appcall-sender" in xtg.g[p][sr].get("kinds", ()) for p in preds
            ), "no appcall-sender edge into callee Sender read"

    def test_return_bridge_targets_caller_logs_read(self, xtg):
        # A callee log feeds the caller's itxna Logs read.
        logs_reads = [
            xn for xn in xtg.nodes()
            if xtg.op_of(xn) in ("itxn", "itxna", "itxnas")
            and (xtg.immediates_of(xn) or "").split()[:1] == ["Logs"]
        ]
        assert logs_reads, "caller Logs read node missing"
        for lr in logs_reads:
            preds = list(xtg.g.predecessors(lr))
            assert any(
                "appcall-return" in xtg.g[p][lr].get("kinds", ()) for p in preds
            ), "no appcall-return edge into caller Logs read"


class TestDetector:
    def test_attacker_arg_reaches_callee_payment_sink(self, xtg):
        from tealql.tealtools.dataflow.xcontract_taint_graph import cross_taint_findings

        findings = cross_taint_findings(xtg)
        assert findings, "expected a cross-contract taint finding"
        # The forwarded ApplicationArgs[0] should land on the callee's
        # itxn_field Receiver.
        receiver_hits = [
            f for f in findings if f.sink_name == "itxn_field Receiver"
        ]
        assert receiver_hits, f"no Receiver-sink finding; got {[f.sink_name for f in findings]}"
        f = receiver_hits[0]
        # Source is a caller-scope ApplicationArgs read; sink is in the callee.
        assert f.source.app_id is None
        assert f.sink.app_id == 1234567
        # The witness path must actually cross the boundary (caller -> callee).
        scopes = [n.app_id for n in f.path]
        assert None in scopes and 1234567 in scopes, scopes
