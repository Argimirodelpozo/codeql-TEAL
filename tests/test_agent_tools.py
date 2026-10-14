"""The agent tool registry (``tealql.agent.tools``) and the contract brief.

Pins the CONTRACT an LLM agent relies on: every tool has a well-formed input
schema and refuses malformed calls; results are JSON-serialisable and carry the
completeness envelope; findings use the versioned ``Finding`` schema; mode
filtering is replayed into ``programs`` so "not applicable" is distinguishable
from "ran clean"; reachability results label themselves as over-approximate.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tealql.agent import tools as T
from tealql.agent.brief import contract_brief, render_brief_markdown
from tealql.cli.main import main
from tealql.security import DETECTORS

TESTS = Path(__file__).resolve().parent
REPRO = TESTS / "contracts" / "repro" / "approval.teal"           # ABI app, `// repro.py:N` comments
UNGUARDED = TESTS / "benchmark" / "tainted-fund-flow" / "vuln" / "unguarded_receiver.teal"
REKEY_VULN_DIR = TESTS / "benchmark" / "rekey-to" / "vuln"        # logicsig-mode detector


def _json_roundtrip(payload) -> dict:
    return json.loads(json.dumps(payload, default=str))


# ---------------------------------------------------------------------------
# registry + argument contract
# ---------------------------------------------------------------------------


def test_every_tool_schema_is_well_formed_and_callable_contract_holds():
    for name, tool in T.TOOLS.items():
        s = tool.input_schema
        assert name.startswith("tealql_") and tool.description
        assert s["type"] == "object" and s["additionalProperties"] is False
        for prop, spec in s["properties"].items():
            assert "type" in spec, (name, prop)
        assert set(s["required"]) <= set(s["properties"]), name
        d = tool.mcp_descriptor()
        assert d["name"] == name and d["inputSchema"] is s
        assert d["annotations"]["openWorldHint"] is (name == "tealql_audit_app")
    # Malformed calls are the caller's error, never a crash deep in the analysis.
    with pytest.raises(T.ToolError, match="unknown argument"):
        T.call_tool("tealql_analyze", {"bogus": 1})
    with pytest.raises(T.ToolError, match="must be integer"):
        T.call_tool("tealql_source_context", {"target": str(REPRO), "line": "17"})
    with pytest.raises(T.ToolError, match="must be one of"):
        T.call_tool("tealql_analyze", {"target": str(REPRO), "mode": "lsig"})
    with pytest.raises(T.ToolError, match="missing required"):
        T.call_tool("tealql_source_context", {"target": str(REPRO)})
    with pytest.raises(T.ToolError, match="exactly one of"):
        T.call_tool("tealql_analyze", {"target": str(REPRO), "teal": "int 1"})
    with pytest.raises(T.ToolError, match="exactly one of"):
        T.call_tool("tealql_analyze", {})
    with pytest.raises(T.ToolError, match="unknown tool"):
        T.call_tool("tealql_nope", {})
    with pytest.raises(T.ToolError, match="does not exist"):
        T.call_tool("tealql_analyze", {"target": "/nonexistent/x.teal"})


def test_list_detectors_mirrors_the_registry_with_metadata():
    out = _json_roundtrip(T.call_tool("tealql_list_detectors"))
    names = [d["name"] for d in out["detectors"]]
    assert names == list(DETECTORS)
    for d in out["detectors"]:
        assert d["severity"] in out["severity_order"]
        assert d["confidence"] in ("high", "medium", "low")
        assert set(d["applies_to"]) <= {"app", "logicsig"} and d["applies_to"]
        assert d["summary"] and not d["summary"].startswith("#")
    by = {d["name"]: d for d in out["detectors"]}
    assert by["rekey-to"]["applies_to"] == ["logicsig"]
    assert by["constant-condition"]["in_default_run"] is False


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


def test_analyze_single_file_emits_versioned_findings_and_mode_aware_run_list():
    out = _json_roundtrip(T.call_tool("tealql_analyze", {"target": str(UNGUARDED)}))
    assert out["complete"] is True and out["notifications"] == []
    assert out["schema_version"] == 1
    hits = {f["rule_id"]: f for f in out["findings"]}
    ff = hits["tainted-fund-flow"]
    # The normalized Finding schema, plus the agent-layer additions.
    assert {"rule_id", "severity", "confidence", "message", "file", "line",
            "fingerprint", "fails"} <= set(ff)
    assert ff["file"] == "unguarded_receiver.teal" and ff["line"] == 4
    assert ff["witness"] == {"sources": ["ApplicationArgs"]}
    assert ff["details"]["field"] == "Receiver"
    assert out["summary"]["total"] == len(out["findings"]) >= 1
    assert out["summary"]["by_detector"]["tainted-fund-flow"] == 1
    # Severity-sorted, worst first.
    sev = [f["severity"] for f in out["findings"]]
    order = ["critical", "high", "medium", "low", "informational"]
    assert sev == sorted(sev, key=order.index)
    # auto mode classified the file as an app (itxn opcodes) and ran only app detectors.
    (ran,) = out["programs"].values()
    assert ran["mode"] == "app"
    assert "tainted-fund-flow" in ran["detectors"] and "rekey-to" not in ran["detectors"]


def test_analyze_mode_filter_and_detector_selection_on_a_logicsig_corpus():
    auto = _json_roundtrip(T.call_tool("tealql_analyze", {"target": str(REKEY_VULN_DIR)}))
    assert auto["complete"] is True
    assert auto["summary"]["by_detector"].get("rekey-to", 0) >= len(list(REKEY_VULN_DIR.glob("*.teal")))
    assert all(p["mode"] == "logicsig" for p in auto["programs"].values())
    # Declaring the wrong mode must not silently report "clean": the run list
    # shows rekey-to did not run.
    app = _json_roundtrip(T.call_tool("tealql_analyze", {"target": str(REKEY_VULN_DIR), "mode": "app"}))
    assert "rekey-to" not in app["summary"]["by_detector"]
    assert all("rekey-to" not in p["detectors"] for p in app["programs"].values())
    only = _json_roundtrip(T.call_tool("tealql_analyze",
                                       {"target": str(REKEY_VULN_DIR), "detectors": ["rekey-to"],
                                        "fail_on": "critical"}))
    assert set(only["summary"]["by_detector"]) == {"rekey-to"}
    assert only["summary"]["failing"] == 0 and all(not f["fails"] for f in only["findings"])
    with pytest.raises(T.ToolError, match="unknown detector"):
        T.call_tool("tealql_analyze", {"target": str(REKEY_VULN_DIR), "detectors": ["nope"]})


def test_analyze_inline_teal_is_materialised_once_and_degradation_is_data():
    teal = "#pragma version 8\nint 1\nreturn\n"
    a = T.call_tool("tealql_analyze", {"teal": teal, "mode": "app"})
    b = T.call_tool("tealql_analyze", {"teal": teal, "mode": "app"})
    assert a["target"] == b["target"] and a["target"].endswith("contract.teal")
    assert a["complete"] is True
    # An opcode unknown to this build must surface as incomplete, not as clean.
    bad = T.call_tool("tealql_analyze", {"teal": "#pragma version 8\nfrobnicate\nint 1\nreturn\n"})
    assert bad["complete"] is False
    assert any("frobnicate" in n["message"] or "parse" in n["kind"] for n in bad["notifications"])


# ---------------------------------------------------------------------------
# verify / taint / context / methods
# ---------------------------------------------------------------------------


def test_verify_sinks_confirms_the_unguarded_receiver_and_explains_labels():
    out = _json_roundtrip(T.call_tool("tealql_verify_sinks", {"target": str(UNGUARDED)}))
    assert out["counts"] == {"CONFIRMED": 1}
    (v,) = out["verdicts"]
    assert v["verdict"] == "CONFIRMED" and v["confirmed_by"] == ["tainted-fund-flow"]
    assert (v["file"], v["line"], v["field"]) == ("unguarded_receiver.teal", 4, "Receiver")
    assert set(out["semantics"]) == {"CONFIRMED", "NOT_FLAGGED", "UNVERIFIED"}


def test_taint_query_modes_are_exclusive_and_labelled_over_approximate():
    to = T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "to_line": 4})
    assert [(s["line"], s["op"]) for s in to["sources"]] == [(3, "txn ApplicationArgs 0")]
    assert "OVER-approximates" in to["semantics"]
    frm = T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "from_line": 3})
    assert [(h["line"], h["category"]) for h in frm["hits"]] == [(4, "inner-payment-receiver")]
    inv = T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "inventory": "sinks"})
    assert {h["field"] for h in inv["hits"]} == {"Receiver", "Amount"}
    surface = T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "precise": True})
    assert surface["query"] == {"attack_surface": True} and surface["hits"]
    with pytest.raises(T.ToolError, match="at most one"):
        T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "to_line": 4, "from_line": 3})
    with pytest.raises(T.ToolError, match="FILE:\\]LINE"):
        T.call_tool("tealql_taint_query", {"target": str(UNGUARDED), "from_source": "x.py"})


def test_source_context_joins_window_source_map_method_predicates_and_taint():
    ctx = _json_roundtrip(T.call_tool("tealql_source_context",
                                      {"target": str(REPRO), "line": 17, "before": 2, "after": 1}))
    assert [w["line"] for w in ctx["window"]] == [15, 16, 17, 18]
    assert [w["focus"] for w in ctx["window"]] == [False, False, True, False]
    assert ctx["window"][2]["text"].strip() == "return"
    assert ctx["high_level_source"] == "repro.py:5"      # from the compiler's comments
    assert ctx["instruction"]["op"] == "return"
    assert ctx["path_predicates"] == []                  # entry fall-through exit: nothing established
    # Inside the routed method the ABI attribution kicks in.
    inner = T.call_tool("tealql_source_context", {"target": str(REPRO), "line": 30})
    assert inner["abi_method"]["name"] == "known_method"
    # A line carrying a sink reports who reaches it and what it reaches.
    sink = T.call_tool("tealql_source_context", {"target": str(UNGUARDED), "line": 4})
    assert [s["line"] for s in sink["attacker_sources_reaching"]] == [3]
    assert [h["category"] for h in sink["sinks_reachable_from"]] == ["inner-payment-receiver"]
    with pytest.raises(T.ToolError, match="out of range"):
        T.call_tool("tealql_source_context", {"target": str(REPRO), "line": 9999})


def test_methods_recovers_table_with_line_spans_and_routability():
    out = T.call_tool("tealql_methods", {"target": str(REPRO)})
    (m,) = out["methods"]
    assert (m["name"], m["signature"], m["selector"]) == ("known_method", "known_method()void", "0xb17ea35d")
    assert m["routable"] is True and m["lines"][0] < m["lines"][1]
    raw = T.call_tool("tealql_methods", {"teal": "#pragma version 8\nint 1\nreturn\n"})
    assert raw["methods"] == []                          # raw bytecode: nothing invented


# ---------------------------------------------------------------------------
# reports, decompile, degraded backends, cache
# ---------------------------------------------------------------------------


def test_reports_carry_the_health_envelope_and_decompile_validates_views():
    itxn = T.call_tool("tealql_inner_transactions", {"target": str(UNGUARDED)})
    assert itxn["complete"] is True
    (group,) = itxn["groups"]
    (txn,) = group["txns"]
    assert {f["name"] for f in txn["fields"]} == {"Receiver", "Amount"}
    shape = T.call_tool("tealql_group_shape", {"target": str(UNGUARDED)})
    assert "shape" in shape and "layout" in shape and shape["complete"] is True
    dec = T.call_tool("tealql_decompile", {"target": str(UNGUARDED)})
    assert dec["view"] == "repr.pre_ir" and dec["complete"] is True
    assert "itxn_field" in dec["text"] and "block@0" in dec["text"]
    with pytest.raises(T.ToolError, match="unknown view"):
        T.call_tool("tealql_decompile", {"target": str(UNGUARDED), "view": "repr.nope"})


def test_backend_gated_tools_degrade_to_incomplete_not_to_clean(monkeypatch):
    monkeypatch.setattr(T, "_cli_json", lambda argv: (2, None, "error: storage-schema requires the 'puya' package"))
    out = T.call_tool("tealql_storage_schema", {"target": str(UNGUARDED)})
    assert out["complete"] is False and out["entries"] == []
    assert out["notifications"][0]["kind"] == "storage-schema-unavailable"
    assert "puya" in out["notifications"][0]["message"]
    with pytest.raises(T.ToolError, match="could not fetch"):
        monkeypatch.setattr(T, "_cli_json", lambda argv: (2, None, "error: could not fetch app 7"))
        T.call_tool("tealql_audit_app", {"app_id": 7})


def test_program_cache_keys_on_content_identity(tmp_path):
    p = tmp_path / "p.teal"
    p.write_text("#pragma version 8\nint 1\nreturn\n")
    a = T.load_program(p)
    assert T.load_program(p) is a
    p.write_text("#pragma version 8\nint 0\nreturn\n")        # size equal, mtime moves
    import os
    os.utime(p, ns=(p.stat().st_atime_ns, p.stat().st_mtime_ns + 1_000_000))
    assert T.load_program(p) is not a


# ---------------------------------------------------------------------------
# brief + CLI
# ---------------------------------------------------------------------------


def test_brief_composes_sections_with_one_envelope_and_renders_markdown():
    b = _json_roundtrip(contract_brief(REPRO))
    assert b["schema"] == "tealql.brief/1" and b["mode"] == "app" and b["avm_version"] == 11
    lc = b["lifecycle"]
    assert lc["updatable"] is True and lc["update_not_creator_gated"] is True
    assert lc["deletable"] is True and lc["delete_not_creator_gated"] is True
    assert b["abi_methods"][0]["name"] == "known_method"
    assert b["attack_surface"] == [] and b["complete"] is True
    assert any(s.startswith("Upgradeable (by anyone") for s in b["headline"])
    assert {f["rule_id"] for f in b["findings"]} >= {"unprotected-updatable", "is-deletable"}
    assert "is-updatable" in b["detectors_run"]
    md = render_brief_markdown(b)
    for heading in ("## ABI methods", "## Lifecycle", "## Findings", "## Analysis health: complete"):
        assert heading in md
    assert "unprotected-updatable @ approval.teal:17" in md
    # A logicsig program: lifecycle detectors do not apply and say so (null).
    lsig = contract_brief(sorted(REKEY_VULN_DIR.glob("*.teal"))[0])
    assert lsig["mode"] == "logicsig" and lsig["lifecycle"]["updatable"] is None
    assert lsig["storage"] == []


def test_cli_brief_explain_and_mcp_list(capsys):
    assert main(["brief", str(REPRO), "--json"]) == 1          # findings -> 1, like `all`
    b = json.loads(capsys.readouterr().out)
    assert b["file"] == "approval.teal" and b["findings"]
    assert main(["brief", str(REPRO)]) == 1
    assert "# approval.teal" in capsys.readouterr().out
    assert main(["explain", str(UNGUARDED), "--line", "4"]) == 0
    out = capsys.readouterr().out
    assert ">>     4" in out and "txn ApplicationArgs 0" in out
    assert main(["explain", str(UNGUARDED), "--line", "4", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["line"] == 4
    assert main(["mcp", "--list-tools"]) == 0
    assert "tealql_verify_sinks" in capsys.readouterr().out
    assert main(["mcp", "--list-tools", "--json"]) == 0
    assert [t["name"] for t in json.loads(capsys.readouterr().out)] == list(T.TOOLS)


def test_diff_matches_findings_across_renames_and_line_shifts(tmp_path, capsys):
    """The revision diff keys findings on rule + message SHAPE: a renamed file
    with a comment inserted at the top must show 0 added / 0 removed, and a fix
    must show exactly the fixed finding as removed."""
    v1 = tmp_path / "v1.teal"
    v2 = tmp_path / "v2.teal"
    v1.write_text(UNGUARDED.read_text())
    v2.write_text("// a comment that shifts every line\n" + UNGUARDED.read_text())
    same = T.call_tool("tealql_diff", {"old": str(v1), "new": str(v2)})
    assert same["summary"]["added"] == 0 and same["summary"]["removed"] == 0
    assert same["summary"]["unchanged"] == same["summary"]["old_total"] >= 1
    assert same["semantic_equivalence"]["status"] in ("PROVED", "UNKNOWN")
    # Pin the receiver to the app: the fund-flow finding goes away, nothing is added.
    fixed = UNGUARDED.read_text().replace("txn ApplicationArgs 0\n    itxn_field Receiver",
                                          "global CurrentApplicationAddress\n    itxn_field Receiver")
    assert fixed != UNGUARDED.read_text()
    v3 = tmp_path / "v3.teal"
    v3.write_text(fixed)
    d = T.call_tool("tealql_diff", {"old": str(v1), "new": str(v3)})
    assert [f["rule_id"] for f in d["removed"]] == ["tainted-fund-flow"] and d["added"] == []
    assert main(["diff", str(v1), str(v3)]) == 0                   # removals are not regressions
    assert "1 removed" in capsys.readouterr().out
    assert main(["diff", str(v3), str(v1)]) == 1                   # the reverse IS one
    assert "1 added" in capsys.readouterr().out
    assert main(["diff", str(v1), str(v3), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["removed"] == 1
    with pytest.raises(T.ToolError):
        T.call_tool("tealql_diff", {"old": str(v1)})
