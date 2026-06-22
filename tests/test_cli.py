"""Unit tests for the ``tealql`` CLI surface.

* Target resolution + the ``finding_to_dict`` helper.
* End-to-end analysis commands (``auth`` / ``group-shape`` / ``cost`` /
  ``itxn-report`` / ``path-predicates`` / ``cfg`` / ``all``) run against the
  committed ``.teal`` fixtures via the pure-Python backend.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tealtools._utils import targets
from cli.main import main
from tealtools._utils.serialize import finding_to_dict


TESTS_ROOT = Path(__file__).resolve().parent
VULN_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "vuln" / "db"
SAFE_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "safe" / "db"


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
