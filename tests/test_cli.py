"""Unit tests for the ``tealql`` CLI surface.

Two layers:

* Pure-Python tests for the parts that don't shell out to ``codeql``
  (target resolution, dir signatures, debug-cache subcommands,
  ``finding_to_dict`` fallback). These always run.
* End-to-end tests for the analyses that do need a real CodeQL DB.
  Each is gated on ``CODEQL`` being on the environment / PATH and
  points at the existing snapshot fixtures so we don't build
  ad-hoc DBs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tealtools import cli, targets
from tealtools.serialize import finding_to_dict


TESTS_ROOT = Path(__file__).resolve().parent
VULN_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "vuln" / "db"
SAFE_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "safe" / "db"


def _has_codeql() -> bool:
    return "CODEQL" in os.environ


requires_codeql = pytest.mark.skipif(
    not _has_codeql(), reason="CODEQL env var not set"
)


# ---------------------------------------------------------------------------
# Pure-Python: target resolution + helpers
# ---------------------------------------------------------------------------


def _make_stub_db(path: Path) -> Path:
    """Minimal directory that satisfies :func:`targets.is_codeql_db`."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "codeql-database.yml").write_text("# stub\n")
    return path


def test_is_codeql_db_true(tmp_path):
    db = _make_stub_db(tmp_path / "db")
    assert targets.is_codeql_db(db)


def test_is_codeql_db_false_for_empty_dir(tmp_path):
    assert not targets.is_codeql_db(tmp_path)


def test_is_codeql_db_false_for_file(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("")
    assert not targets.is_codeql_db(f)


def test_resolve_target_passes_existing_db_through(tmp_path):
    db = _make_stub_db(tmp_path / "db")
    assert targets.resolve_target(db) == db.resolve()


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


def test_dir_signature_stable_under_reread(tmp_path):
    f = tmp_path / "a.teal"
    f.write_text("int 0\nreturn\n")
    assert targets._dir_signature([f]) == targets._dir_signature([f])


def test_dir_signature_changes_on_content_edit(tmp_path):
    f = tmp_path / "a.teal"
    f.write_text("int 0\nreturn\n")
    h1 = targets._dir_signature([f])
    f.write_text("int 1\nreturn\n")
    h2 = targets._dir_signature([f])
    assert h1 != h2


def test_dir_signature_changes_on_basename(tmp_path):
    f1 = tmp_path / "a.teal"
    f1.write_text("int 0\nreturn\n")
    h1 = targets._dir_signature([f1])
    f2 = tmp_path / "b.teal"
    f1.rename(f2)
    h2 = targets._dir_signature([f2])
    assert h1 != h2


def test_dir_signature_order_independent(tmp_path):
    (tmp_path / "a.teal").write_text("a\n")
    (tmp_path / "b.teal").write_text("b\n")
    f1, f2 = tmp_path / "a.teal", tmp_path / "b.teal"
    assert targets._dir_signature([f1, f2]) == targets._dir_signature([f2, f1])


def test_search_path_locates_repo_extractors():
    # The repo ships ``.codeql-extractors/`` alongside this checkout;
    # walking parents from ``targets.py`` must find it.
    sp = targets._search_path()
    assert sp is not None
    assert Path(sp).name == ".codeql-extractors"


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
# CLI plumbing: argv parsing + debug subcommands (no codeql)
# ---------------------------------------------------------------------------


def test_cli_exit_code_bad_target(capsys):
    rc = cli.main(["auth", "/tmp/does-not-exist-xyz-tealql"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does not exist" in err


def test_cli_debug_db_passthrough(tmp_path, capsys):
    db = _make_stub_db(tmp_path / "stub-db")
    rc = cli.main(["debug", "db", str(db)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == str(db.resolve())


def test_cli_debug_db_json(tmp_path, capsys):
    db = _make_stub_db(tmp_path / "stub-db")
    rc = cli.main(["debug", "db", str(db), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"db": str(db.resolve())}


def test_cli_debug_cache_info_empty(tmp_path, capsys):
    rc = cli.main([
        "debug", "cache", "info",
        "--db-cache", str(tmp_path / "empty-cache"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exists"] is False
    assert payload["entries"] == 0


def test_cli_debug_cache_info_populated(tmp_path, capsys):
    cache = tmp_path / "cache"
    (cache / "abc123").mkdir(parents=True)
    (cache / "def456").mkdir(parents=True)
    rc = cli.main([
        "debug", "cache", "info",
        "--db-cache", str(cache),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exists"] is True
    assert payload["entries"] == 2
    assert sorted(payload["ids"]) == ["abc123", "def456"]


def test_cli_debug_cache_clear(tmp_path, capsys):
    cache = tmp_path / "cache"
    (cache / "xyz").mkdir(parents=True)
    rc = cli.main(["debug", "cache", "clear", "--db-cache", str(cache)])
    assert rc == 0
    assert not cache.exists()


# ---------------------------------------------------------------------------
# End-to-end: exit codes + JSON shape (need codeql)
# ---------------------------------------------------------------------------


@requires_codeql
def test_cli_exit_zero_on_clean(capsys):
    rc = cli.main(["auth", str(SAFE_DB)])
    assert rc == 0
    assert "no violations" in capsys.readouterr().out


@requires_codeql
def test_cli_exit_one_on_findings(capsys):
    rc = cli.main(["auth", str(VULN_DB)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "app_global_put" in out
    assert "prog.teal" in out


@requires_codeql
def test_cli_json_auth_shape(capsys):
    cli.main(["auth", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert data, "expected at least one violation"
    v = data[0]
    assert {"sink", "dominating_predicates"} <= v.keys()
    assert {"op", "file", "line", "class"} <= v["sink"].keys()
    assert v["sink"]["file"] == "prog.teal"
    assert isinstance(v["sink"]["line"], int)


@requires_codeql
def test_cli_json_group_shape_keys(capsys):
    cli.main(["group-shape", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "constraints" in data
    assert isinstance(data["constraints"], list)


@requires_codeql
def test_cli_json_cost_keys(capsys):
    cli.main(["cost", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "entries" in data
    for e in data["entries"]:
        assert {"file", "line", "op", "op_cost", "cumulative"} <= e.keys()
        assert isinstance(e["line"], int)
        assert isinstance(e["op_cost"], int)


@requires_codeql
def test_cli_json_itxn_report_keys(capsys):
    cli.main(["itxn-report", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "groups" in data
    assert isinstance(data["groups"], list)


@requires_codeql
def test_cli_json_path_predicates_keys(capsys):
    cli.main(["path-predicates", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "blocks" in data
    for bb in data["blocks"]:
        assert {"file", "first_line", "last_line", "predicates"} <= bb.keys()


@requires_codeql
def test_cli_json_cfg_wraps_dot(capsys):
    cli.main(["cfg", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["format"] == "dot"
    assert data["dot"].startswith("digraph")


@requires_codeql
def test_cli_json_all_aggregator(capsys):
    cli.main(["all", str(VULN_DB), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert {"detectors", "reports"} <= data.keys()
    # Every detector key maps to a list (possibly empty).
    for name, findings in data["detectors"].items():
        assert isinstance(findings, list), name
    # Every report key has a structured payload.
    assert {"itxn-report", "group-shape", "cost", "path-predicates"} <= data["reports"].keys()
