"""Unit tests for the ``tealql`` CLI surface.

* Target resolution + the ``finding_to_dict`` helper.
* End-to-end analysis commands (``auth`` / ``group-shape`` / ``cost`` /
  ``itxn-report`` / ``path-predicates`` / ``cfg`` / ``all``) run against the
  committed ``.teal`` fixtures via the pure-Python backend.
* Security subcommands (``detections`` / ``detections-scan``) — smoke +
  exit-code + JSON-shape coverage (the ``render_json`` regression that broke
  ``detections-scan`` was invisible without these).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tealtools._utils import targets
from cli.main import main
from tealtools._utils.serialize import finding_to_dict


TESTS_ROOT = Path(__file__).resolve().parent
VULN_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "vuln"
SAFE_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "safe"
REKEY_VULN_DIR = TESTS_ROOT / "benchmark" / "rekey-to" / "vuln"


# ---------------------------------------------------------------------------
# Pure-Python: target resolution + helpers
# ---------------------------------------------------------------------------


def test_resolve_target_teal_file(tmp_path):
    f = tmp_path / "prog.teal"
    f.write_text("#pragma version 8\nint 1\n")
    assert targets.resolve_target(f) == f.resolve()


def test_resolve_target_teal_dir(tmp_path):
    (tmp_path / "a.teal").write_text("#pragma version 8\nint 1\n")
    assert targets.resolve_target(tmp_path) == tmp_path.resolve()


def test_resolve_target_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        targets.resolve_target(tmp_path / "does-not-exist")


def test_resolve_target_empty_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        targets.resolve_target(tmp_path)


def test_resolve_target_nonteal_file_raises(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("")
    with pytest.raises(ValueError):
        targets.resolve_target(f)


# ---------------------------------------------------------------------------
# Pure-Python: finding_to_dict fallback
# ---------------------------------------------------------------------------


class _HasToDict:
    def to_dict(self):
        return {"a": 1}

    def pretty(self):
        return "should-not-be-used"


class _JustPretty:
    def pretty(self):
        return "fallback msg"


class _BareString:
    def __str__(self):
        return "stringified"


def test_finding_to_dict_prefers_to_dict():
    assert finding_to_dict(_HasToDict()) == {"a": 1}


def test_finding_to_dict_falls_back_to_pretty():
    assert finding_to_dict(_JustPretty()) == {"message": "fallback msg"}


def test_finding_to_dict_last_resort_str():
    assert finding_to_dict(_BareString()) == {"message": "stringified"}


# ---------------------------------------------------------------------------
# CLI plumbing: argv parsing
# ---------------------------------------------------------------------------


def test_cli_exit_code_bad_target(capsys):
    rc = main(["auth", "/tmp/does-not-exist-xyz-tealql"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does not exist" in err


# ---------------------------------------------------------------------------
# End-to-end: exit codes + JSON shape (pure-Python backend)
# ---------------------------------------------------------------------------


def test_cli_exit_zero_on_clean(capsys):
    rc = main(["auth", str(SAFE_DB)])
    assert rc == 0
    assert "no violations" in capsys.readouterr().out


def test_cli_exit_one_on_findings(capsys):
    rc = main(["auth", str(VULN_DB)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "app_global_put" in out
    assert "prog.teal" in out


def test_cli_json_auth_shape(capsys):
    main(["auth", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert data, "expected at least one violation"
    v = data[0]
    assert {"sink", "dominating_predicates"} <= v.keys()
    assert {"op", "file", "line", "class"} <= v["sink"].keys()
    assert v["sink"]["file"] == "prog.teal"
    assert isinstance(v["sink"]["line"], int)


def test_cli_json_group_shape_keys(capsys):
    main(["group-shape", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "constraints" in data
    assert isinstance(data["constraints"], list)


def test_cli_json_cost_keys(capsys):
    main(["cost", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "entries" in data
    for e in data["entries"]:
        assert {"file", "line", "op", "op_cost", "cumulative"} <= e.keys()
        assert isinstance(e["line"], int)
        assert isinstance(e["op_cost"], int)


def test_cli_json_itxn_report_keys(capsys):
    main(["itxn-report", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "groups" in data
    assert isinstance(data["groups"], list)


def test_cli_json_path_predicates_keys(capsys):
    main(["path-predicates", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "blocks" in data
    for bb in data["blocks"]:
        assert {"file", "first_line", "last_line", "predicates"} <= bb.keys()


def test_cli_json_cfg_wraps_dot(capsys):
    main(["cfg", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["format"] == "dot"
    assert data["dot"].startswith("digraph")


def test_cli_json_all_aggregator(capsys):
    main(["all", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert {"detectors", "reports"} <= data.keys()
    # Every detector key maps to a list (possibly empty).
    for name, findings in data["detectors"].items():
        assert isinstance(findings, list), name
    # Every report key has a structured payload.
    assert {"itxn-report", "group-shape", "cost", "path-predicates"} <= data["reports"].keys()


def test_cli_functional_smoke(capsys):
    # `tealql functional` crashed with ImportError after passes/orchestrate.py
    # was deleted as dead code (86f3730d) — the CLI handler was its live caller.
    rc = main(["functional", str(VULN_DB), "--show-ranges", "--show-bytes"])
    assert rc == 0
    assert capsys.readouterr().out.strip()


def test_cli_functional_by_block(capsys):
    rc = main(["functional", str(VULN_DB), "--by-block"])
    assert rc == 0
    assert "# BB(" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# End-to-end: security subcommands (detections / detections-scan)
# ---------------------------------------------------------------------------


def test_cli_detections_single_detector_findings(capsys):
    rc = main(["detections", str(REKEY_VULN_DIR / "no_check.teal"),
               "--detector", "rekey-to"])
    assert rc == 1
    assert capsys.readouterr().out.strip()


def test_cli_detections_list(capsys):
    rc = main(["detections", "--list"])
    assert rc == 0
    names = capsys.readouterr().out.split()
    assert "rekey-to" in names
    assert "ir-tainted-fund-flow" in names


def test_cli_detections_scan_text_exit_one_on_findings(capsys):
    rc = main(["detections-scan", str(REKEY_VULN_DIR)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "sec-guide/rekey-to" in out


def test_cli_detections_scan_json_shape(capsys):
    rc = main(["detections-scan", str(REKEY_VULN_DIR), "--json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    # Versioned envelope, not a bare list.
    assert data["schema_version"] >= 1 and data["tool"] == "tealql"
    findings = data["findings"]
    assert isinstance(findings, list) and findings
    for f in findings:
        assert {"rule_id", "file", "line", "severity", "confidence",
                "message"} <= f.keys()
    rk = [f for f in findings if f["rule_id"] == "rekey-to"]
    assert rk and rk[0]["detector"] == "sec-guide/rekey-to"
    # At least some findings carry a real 1-based line (not just prose).
    assert any(isinstance(f["line"], int) for f in findings)


def test_cli_detections_scan_sarif(capsys):
    rc = main(["detections-scan", str(REKEY_VULN_DIR), "--format", "sarif"])
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "tealql"
    assert run["tool"]["driver"]["rules"]
    res = run["results"]
    assert res and all("ruleId" in r and r["locations"] for r in res)
    # SARIF level maps from severity; high → error.
    assert any(r["level"] == "error" for r in res)


def test_cli_detections_all_drops_superseded(capsys):
    main(["detections", str(SAFE_DB), "--all"])
    out = capsys.readouterr().out
    # --all prints a `=== sec-guide/<name> ===` header per detector run: the
    # IR successor must run, its superseded SSA sibling must not.
    assert "=== sec-guide/ir-tainted-fund-flow ===" in out
    assert "=== sec-guide/tainted-fund-flow ===" not in out


def test_cli_all_runs_ir_family_not_superseded(capsys):
    # `tealql all` derives its detector set from the registry: the ir-*
    # family (the primary detectors) must be present, superseded SSA
    # siblings and on-demand-only detections must not.
    main(["all", str(VULN_DB), "--json"])
    detectors = json.loads(capsys.readouterr().out)["detectors"]
    assert "detections/ir-tainted-fund-flow" in detectors
    assert "detections/ir-arbitrary-inner-appcall" in detectors
    assert "detections/tainted-fund-flow" not in detectors
    assert "detections/abi-method-selector" not in detectors
    assert "detections/constant-condition" not in detectors


XC_FIX = TESTS_ROOT / "tealtools" / "xcontract_sec_guide" / "deletable_callee"


def test_cli_xcontract_default_no_detections(capsys):
    # Without --detections, xcontract runs only cross-contract auth-domination
    # (no "cross-contract security findings" section).
    main(["xcontract", str(XC_FIX / "caller"),
          "--registry", str(XC_FIX / "registry.yml")])
    assert "cross-contract security findings" not in capsys.readouterr().out


def test_cli_xcontract_detections(capsys):
    rc = main(["xcontract", str(XC_FIX / "caller"),
               "--registry", str(XC_FIX / "registry.yml"), "--detections"])
    out = capsys.readouterr().out
    assert "cross-contract security findings" in out
    # The deletable callee is flagged across the boundary.
    assert "sec-guide/is-deletable" in out
    assert rc == 1


def test_cli_xcontract_detector_scoped_json(capsys):
    rc = main(["xcontract", str(XC_FIX / "caller"),
               "--registry", str(XC_FIX / "registry.yml"),
               "--detector", "is-deletable", "--json"])
    data = json.loads(capsys.readouterr().out)
    findings = data["cross_detection_findings"]
    assert findings and all(f["detector"] == "sec-guide/is-deletable"
                            for f in findings)
    assert all({"app_id", "detector", "message"} <= f.keys() for f in findings)
    assert rc == 1


def test_cli_detections_scan_config_empty_only_exit_zero(tmp_path, capsys):
    # A bare approve-everything program fires a dozen detectors by design,
    # so exercise the clean-exit path by scoping the scan to zero detectors
    # via a --config rule (which also covers the config-loading path).
    # NB: "*.teal" not "**/*.teal" — fnmatch's `*` crosses `/`, but a literal
    # `**/` prefix requires a slash in the rel path, which root-level files
    # don't have (the scan.py docstring example has this trap).
    rules = tmp_path / "rules.yml"
    rules.write_text('rules:\n  - match: "*.teal"\n    only: []\n')
    rc = main(["detections-scan", str(REKEY_VULN_DIR), "--config", str(rules)])
    assert rc == 0
    assert "(no findings)" in capsys.readouterr().out
