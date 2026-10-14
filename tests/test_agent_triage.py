"""The agent-side triage loop (``tealql.agent.triage``): the verdict store, the
work queue, staleness, the false-positive baseline export and the benchmark
agreement measurement. Fixtures are COPIED into ``tmp_path`` so no store is
ever written under ``tests/benchmark``."""
from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from tealql.agent import tools as T
from tealql.agent import triage as TR
from tealql.cli.main import main as cli_main

BENCH = Path(__file__).resolve().parent / "benchmark"
UNGUARDED = BENCH / "tainted-fund-flow" / "vuln" / "unguarded_receiver.teal"
CONSTANT = BENCH / "tainted-fund-flow" / "safe" / "constant_receiver.teal"
NO_CHECK = BENCH / "rekey-to" / "vuln" / "no_check.teal"


def _cli(argv) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli_main(argv)
    return rc, out.getvalue()


def _copy(src: Path, dst_dir: Path) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    return Path(shutil.copy(src, dst_dir / src.name))


def _fp(queue: dict, rule: str) -> dict:
    (item,) = [i for i in queue["queue"] if i["rule"] == rule]
    return item


def test_store_round_trip_and_record_validation(tmp_path):
    teal = _copy(UNGUARDED, tmp_path / "app")
    store = tmp_path / "triage.json"
    q = T.call_tool("tealql_triage_queue", {"target": str(teal), "store": str(store)})
    tff = _fp(q, "tainted-fund-flow")
    args = {"target": str(teal), "store": str(store), "fingerprint": tff["fingerprint"]}
    # Validation: every refusal leaves the store untouched (not even created).
    with pytest.raises(T.ToolError, match="not a current finding"):
        T.call_tool("tealql_record_triage", {**args, "fingerprint": "0" * 16,
                                             "verdict": "true_positive", "rationale": "x"})
    with pytest.raises(T.ToolError, match="must be one of"):
        T.call_tool("tealql_record_triage", {**args, "verdict": "bogus", "rationale": "x"})
    with pytest.raises(T.ToolError, match="must be one of"):        # direct API too
        TR.record_triage(**args, verdict="maybe", rationale="x")
    with pytest.raises(T.ToolError, match="must cite evidence_lines"):
        T.call_tool("tealql_record_triage", {**args, "verdict": "false_positive",
                                             "rationale": "guarded"})
    with pytest.raises(T.ToolError, match="outside"):
        T.call_tool("tealql_record_triage", {**args, "verdict": "false_positive",
                                             "rationale": "guarded", "evidence_lines": [999]})
    with pytest.raises(T.ToolError, match="non-empty"):
        T.call_tool("tealql_record_triage", {**args, "verdict": "true_positive",
                                             "rationale": "  "})
    assert not store.exists()
    r = T.call_tool("tealql_record_triage", {**args, "verdict": "true_positive",
                                             "rationale": "receiver is ApplicationArgs 0",
                                             "evidence_lines": [4, 2, 4],
                                             "reviewer": "test-model"})
    assert r["stored"] and not r["replaced"]
    # Round trip: a fresh load sees the record with every field, root relative.
    rec = TR.TriageStore(store).records[r["key"]]
    assert {k: rec[k] for k in ("fingerprint", "rule", "file", "verdict", "reviewer",
                                "evidence_lines")} == {
        "fingerprint": tff["fingerprint"], "rule": "tainted-fund-flow",
        "file": teal.name, "verdict": "true_positive", "reviewer": "test-model",
        "evidence_lines": [2, 4]}
    assert rec["root"] == "app" and rec["timestamp"] and rec["tool_version"]
    assert rec["finding"]["line"] == tff["line"] and "source_context" not in rec["finding"]
    # Advice only: the detector verdict surface is unchanged.
    assert any(f["fingerprint"] == tff["fingerprint"]
               for f in T.call_tool("tealql_analyze", {"target": str(teal)})["findings"])
    # Re-recording replaces; the triaged finding leaves the queue.
    r2 = TR.record_triage(**args, verdict="needs_context", rationale="depends on caller")
    assert r2["replaced"] and len(TR.TriageStore(store).records) == 1
    q2 = TR.triage_queue(target=str(teal), store=str(store))
    assert tff["fingerprint"] not in {i["fingerprint"] for i in q2["queue"]}
    assert q2["summary"]["triaged"] == 1
    # The same file under ANOTHER root is a different finding: not triaged there.
    other = _copy(UNGUARDED, tmp_path / "other")
    assert TR.triage_queue(target=str(other), store=str(store),
                           context=False)["summary"]["triaged"] == 0
    # Default store location: beside the scan root.
    TR.record_triage(target=str(teal), fingerprint=tff["fingerprint"],
                     verdict="true_positive", rationale="r")
    assert (teal.parent / ".tealql" / "triage.json").exists()


def test_queue_orders_by_severity_and_prejoins_source_context(tmp_path):
    teal = _copy(UNGUARDED, tmp_path)
    q = TR.triage_queue(target=str(teal), store=str(tmp_path / "s.json"), limit=2)
    sev = [TR._SEV_RANK[i["severity"]] for i in q["queue"]]
    assert sev == sorted(sev, reverse=True) and q["queue"][-1]["severity"] == "informational"
    assert q["summary"] == {"findings": len(q["queue"]), "triaged": 0,
                            "pending": len(q["queue"]), "with_context": 2}
    for item in q["queue"][:2]:
        ctx = item["source_context"]
        assert ctx["line"] == item["line"] and "path_predicates" in ctx
        assert [w["line"] for w in ctx["window"] if w["focus"]] == [item["line"]]
    assert all("source_context" not in i for i in q["queue"][2:])


def test_record_goes_stale_when_the_program_changes(tmp_path):
    teal = _copy(UNGUARDED, tmp_path)
    store = str(tmp_path / "s.json")
    q = TR.triage_queue(target=str(teal), store=store, context=False)
    fp = _fp(q, "tainted-fund-flow")["fingerprint"]
    TR.record_triage(target=str(teal), store=store, fingerprint=fp,
                     verdict="true_positive", rationale="unguarded receiver")
    rep = TR.triage_report(target=str(teal), store=store)
    assert [r["fingerprint"] for r in rep["records"]] == [fp] and rep["stale"] == []
    # The receiver gets pinned to a constant: that finding is no longer produced.
    teal.write_text(CONSTANT.read_text())
    rc, out = _cli(["triage", str(teal), "--store", store, "--json"])
    rep = json.loads(out)
    assert rc == 0 and rep["records"] == []
    assert [r["fingerprint"] for r in rep["stale"]] == [fp]
    assert rep["summary"]["stale_records"] == 1 and rep["summary"]["by_verdict"] == {}


def test_exported_baseline_suppresses_exactly_the_false_positive_findings(tmp_path):
    root = tmp_path / "repo"
    teal = _copy(UNGUARDED, root)
    store = str(tmp_path / "s.json")
    q = TR.triage_queue(target=str(root), store=store, context=False)
    fp_upd = _fp(q, "unprotected-updatable")["fingerprint"]
    fp_tff = _fp(q, "tainted-fund-flow")["fingerprint"]
    TR.record_triage(target=str(root), store=store, fingerprint=fp_upd,
                     verdict="false_positive", rationale="update gated", evidence_lines=[9])
    TR.record_triage(target=str(root), store=store, fingerprint=fp_tff,
                     verdict="true_positive", rationale="real")
    base = tmp_path / "baseline.json"
    rc, _ = _cli(["triage", str(root), "--store", store, "--export-baseline", str(base)])
    data = json.loads(base.read_text())
    assert rc == 0 and data["version"] == 2 and data["fingerprints"] == [fp_upd]
    assert data["triage"][0]["rationale"] == "update gated" and teal.exists()

    def scan(*extra):
        _rc, out = _cli(["detections-scan", str(root), "--json", *extra])
        return [(f["rule_id"], f["line"]) for f in json.loads(out)["findings"]]
    before, after = scan(), scan("--baseline", str(base))
    gone = [f for f in before if f not in after]
    assert len(after) == len(before) - 1 and gone and "unprotected-updatable" in gone[0][0]


def test_triage_eval_agreement_over_benchmark_fixtures(tmp_path):
    bench = tmp_path / "benchmark"
    tff = _copy(UNGUARDED, bench / "tainted-fund-flow" / "vuln")
    rk = _copy(NO_CHECK, bench / "rekey-to" / "vuln")
    store = str(tmp_path / "s.json")
    q1 = TR.triage_queue(target=str(tff), store=store, context=False)
    q2 = TR.triage_queue(target=str(rk), store=store, context=False)
    TR.record_triage(target=str(tff), store=store, verdict="true_positive", rationale="a",
                     fingerprint=_fp(q1, "tainted-fund-flow")["fingerprint"])
    TR.record_triage(target=str(rk), store=store, verdict="false_positive", rationale="b",
                     fingerprint=_fp(q2, "rekey-to")["fingerprint"], evidence_lines=[3])
    # Another detector's finding on a fixture carries no label for it.
    TR.record_triage(target=str(rk), store=store, verdict="true_positive", rationale="c",
                     fingerprint=_fp(q2, "fee-validation")["fingerprint"])
    # Synthetic records on SAFE fixtures (the detector would be wrong there):
    # false_positive agrees with the label, needs_context abstains.
    data = json.loads(Path(store).read_text())
    for name, verdict in (("x.teal", "false_positive"), ("y.teal", "needs_context")):
        data["records"][f"f{name}:rekey-to:{name}"] = {
            "fingerprint": "f" + name, "rule": "rekey-to", "file": name,
            "root": "benchmark/rekey-to/safe", "verdict": verdict, "rationale": "s",
            "evidence_lines": [1], "reviewer": "t", "timestamp": "", "tool_version": "",
            "finding": {}}
    Path(store).write_text(json.dumps(data))
    ev = TR.evaluate_against_benchmark(store)
    assert ev["per_detector"] == {
        "rekey-to": {"agree": 1, "disagree": 1, "abstain": 1, "agreement": 0.5},
        "tainted-fund-flow": {"agree": 1, "disagree": 0, "abstain": 0, "agreement": 1.0}}
    assert ev["overall"]["agreement"] == round(2 / 3, 4) and ev["unlabelled"] == 1
    assert [(d["rule"], d["label"]) for d in ev["disagreements"]] == [("rekey-to", "vuln")]
    rc, out = _cli(["triage-eval", "--store", store])
    assert rc == 0 and "66.7%" in out and "DISAGREE rekey-to" in out
