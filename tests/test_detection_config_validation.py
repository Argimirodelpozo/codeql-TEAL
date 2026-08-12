"""Config validation, glob normalization, --options wiring, per-file
directory semantics, and severity precedence.

These close the "a typo silently changes what gets scanned / how it
exits" class: a bad detector name, a both-only-and-exclude rule, an
unknown key — each now fails loudly at load time instead of quietly
altering coverage.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.cli.main import main
from tealql.security import DETECTORS, severity_of
from tealql.security.config import ConfigError, DetectionConfig, glob_match
from tealql.security.scan import DetectionOptions, ScanFinding

TESTS_ROOT = Path(__file__).resolve().parent
REKEY_VULN_DIR = TESTS_ROOT / "benchmark" / "rekey-to" / "vuln"


# ---------------------------------------------------------------------------
# glob normalization (the **/ root-level trap)
# ---------------------------------------------------------------------------


def test_glob_double_star_prefix_matches_root_level():
    # The scan.py docstring's own catch-all example missed root-level files.
    assert glob_match("prog.teal", "**/*.teal")
    assert glob_match("sub/prog.teal", "**/*.teal")
    assert glob_match("prog.teal", "*.teal")


def test_glob_plain_star_crosses_slash():
    assert glob_match("a/b/lsig.teal", "*lsig*")


# ---------------------------------------------------------------------------
# Detector-selection validation through the unified options schema
# ---------------------------------------------------------------------------


def test_options_unknown_detector_in_only_rejected():
    with pytest.raises(ConfigError, match="unknown detector"):
        DetectionOptions.from_dict({"detectors": [{"match": "*.teal",
                                                    "only": ["rekey-to", "reeky-to"]}]})


def test_options_unknown_detector_in_exclude_rejected():
    with pytest.raises(ConfigError, match="unknown detector"):
        DetectionOptions.from_dict({"detectors": [{"match": "*.teal",
                                                    "exclude": ["notadetector"]}]})


def test_options_only_and_exclude_together_rejected():
    with pytest.raises(ConfigError, match="mutually"):
        DetectionOptions.from_dict({"detectors": [{"match": "*.teal",
                                                    "only": ["rekey-to"],
                                                    "exclude": ["fee-validation"]}]})


def test_options_missing_match_rejected():
    with pytest.raises(ConfigError, match="missing 'match'"):
        DetectionOptions.from_dict({"detectors": [{"only": ["rekey-to"]}]})


def test_options_unknown_rule_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        DetectionOptions.from_dict({"detectors": [{"match": "*.teal",
                                                    "onyl": ["rekey-to"]}]})


def test_options_valid_selection_roundtrips():
    cfg = DetectionOptions.from_dict({"detectors": [
        {"match": "*lsig*.teal", "only": ["rekey-to", "fee-validation"]},
        {"match": "*.teal", "exclude": ["unsafe-lsig-args"]},
    ]})
    assert len(cfg.selection.rules) == 2


def test_options_from_path_rejects_old_rules_key(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("rulez:\n  - match: '*.teal'\n")
    with pytest.raises(ConfigError, match="unknown top-level"):
        DetectionOptions.from_path(p)


# ---------------------------------------------------------------------------
# DetectionConfig (modes) validation
# ---------------------------------------------------------------------------


def test_modeconfig_bad_mode_rejected():
    with pytest.raises(ConfigError, match="invalid 'mode'"):
        DetectionConfig.from_dict({"modes": [{"match": "*.teal",
                                              "mode": "lsig"}]})


def test_modeconfig_unknown_rule_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        DetectionConfig.from_dict({"modes": [{"match": "*.teal",
                                              "mode": "app", "moed": "x"}]})


# ---------------------------------------------------------------------------
# DetectionOptions validation
# ---------------------------------------------------------------------------


def test_options_unknown_severity_detector_rejected():
    with pytest.raises(ConfigError, match="unknown detector"):
        DetectionOptions.from_dict({"severity": {"nope": "high"}})


def test_options_unknown_top_key_rejected():
    with pytest.raises(ConfigError, match="unknown top-level"):
        DetectionOptions.from_dict({"detector": []})  # should be "detectors"


def test_options_bad_fail_on_rejected():
    with pytest.raises(ConfigError, match="fail_on"):
        DetectionOptions.from_dict({"fail_on": "showstopper"})


# ---------------------------------------------------------------------------
# --options CLI wiring + fail_on exit code
# ---------------------------------------------------------------------------


def test_cli_options_fail_on_gates_exit_code(tmp_path, capsys):
    # is-deletable/is-updatable are informational; a scan of a bare
    # approve-all program with fail_on: high must report but exit 0.
    (tmp_path / "prog.teal").write_text(
        "#pragma version 8\nint 1\nreturn\n")
    opts = tmp_path / "opts.yml"
    opts.write_text("detectors:\n  - match: '*.teal'\n    only: [is-deletable]\n"
                    "fail_on: high\n")
    rc = main(["detections-scan", str(tmp_path), "--options", str(opts)])
    out = capsys.readouterr().out
    assert "sec-guide/is-deletable" in out   # reported
    assert rc == 0                           # but not a failure


def test_cli_rejects_removed_config_flag(tmp_path, capsys):
    cfg = tmp_path / "c.yml"
    cfg.write_text("rules: []\n")
    with pytest.raises(SystemExit, match="2"):
        main(["detections-scan", str(tmp_path), "--config", str(cfg)])
    assert "unrecognized arguments" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# applies_to declarations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "rekey-to", "fee-validation", "close-remainder-to",
    "asset-close-to", "asset-id-validation",
])
def test_signed_txn_field_detectors_are_logicsig_scoped(name):
    assert getattr(DETECTORS[name], "applies_to", None) == frozenset({"logicsig"})


# ---------------------------------------------------------------------------
# Severity: declared, and violation-level flows into ScanFinding
# ---------------------------------------------------------------------------


def test_property_detectors_informational():
    assert severity_of("is-deletable") == "informational"
    assert severity_of("is-updatable") == "informational"


def test_finding_detectors_declare_non_default_severity():
    # After the pass, none of the real-vuln detectors sit on the bare default.
    for name in ("rekey-to", "fee-validation", "close-remainder-to",
                 "tx-type-check", "group-size-check"):
        assert severity_of(name) == "high", name


def test_scanfinding_uses_violation_severity_when_present():
    class _V:
        severity = "critical"

        def pretty(self):
            return "drain"

    f = ScanFinding(rel_path=Path("p.teal"), detector_name="rekey-to",
                    violation=_V())
    # rekey-to's class severity is "high", but the violation grades critical.
    assert f.severity == "critical"


def test_scanfinding_override_beats_violation():
    class _V:
        severity = "critical"

        def pretty(self):
            return "x"

    f = ScanFinding(rel_path=Path("p.teal"), detector_name="rekey-to",
                    violation=_V(), severity_override="low")
    assert f.severity == "low"


# ---------------------------------------------------------------------------
# Per-file semantics: `detections <dir>` runs one program per file
# ---------------------------------------------------------------------------


def test_cli_detections_dir_runs_per_file(capsys):
    # The rekey-to vuln dir has 3 independent programs; a per-file run must
    # report a finding anchored in each, not a single merged-program result.
    rc = main(["detections", str(REKEY_VULN_DIR), "--detector", "rekey-to"])
    assert rc == 1
    out = capsys.readouterr().out
    files = {line.split(":")[0].strip() for line in out.splitlines()
             if ".teal" in line}
    assert len(files) >= 2, out
