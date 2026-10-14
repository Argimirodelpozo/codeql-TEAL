"""Output-contract defects from the 2026-10-10 review (reports/output.md), one
test per defect with its control folded in.

B1  baseline fingerprints collided across distinct approval exits
B2  fingerprints were not line-insensitive for messages carrying `@L4` / `line N`
B3  `detections --json` / `all --json` emitted raw `{message}` dicts, not the Finding schema
B4  SARIF lacked partialFingerprints / helpUri / help and forced whole-program findings to line 1
B5  `taint-query` / `group-taint` JSON had no completeness envelope and exited 0 on degraded input
B6  inline suppression ignored the `sec-guide/` prefix and space-separated lists
B8  `--from-src LINE` (no file) matched nothing; B9 a bare basename unioned every `*/file.py`
B10 whole-program findings could only be suppressed from the `#pragma` line
B11 `--baseline PATH` with a missing file was silently an empty baseline
B13 notifications dropped the degradation's line
A14 `finding_to_dict` ignored a violation's `.file`/`.line`
A15 `detections --all` had no opcode-classified mode
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tealql.cli.main import main
from tealql.security.scan import DetectionOptions, render_sarif, scan
from tealql.security.suppress import (
    FINGERPRINT_VERSION, fingerprints, load_baseline, partition, write_baseline,
)
from tealql.tealtools._utils.serialize import finding_to_dict

TESTS = Path(__file__).resolve().parent
UNGUARDED = TESTS / "benchmark" / "tainted-fund-flow" / "vuln" / "unguarded_receiver.teal"

_ONLY_REKEY = DetectionOptions.from_dict({"detectors": [{"match": "*", "only": ["rekey-to"]}]})
_ONE_EXIT = "#pragma version 8\ntxn Amount\nbz second\nint 1\nreturn\nsecond:\nint 0\nreturn\n"
_TWO_EXITS = "#pragma version 8\ntxn Amount\nbz second\nint 1\nreturn\nsecond:\nint 1\nreturn\n"


def _scan_one(tmp_path: Path, name: str, teal: str, options=None):
    d = tmp_path / name
    d.mkdir()
    (d / "p.teal").write_text(teal)
    return d, scan(d, options=options)


def test_b1_b2_fingerprints_distinguish_exits_and_survive_line_shifts(tmp_path):
    # B1: a second unguarded exit whose message differs only by line number must
    # NOT be covered by a baseline written for the first.
    d1, one = _scan_one(tmp_path, "v1", _ONE_EXIT, _ONLY_REKEY)
    d2, two = _scan_one(tmp_path, "v2", _TWO_EXITS, _ONLY_REKEY)
    assert len(one) == 1 and len(two) == 2
    assert len(set(fingerprints(two))) == 2, "two exits, two fingerprints"
    bl = tmp_path / "bl.json"
    write_baseline(bl, one)
    kept, suppressed = partition(list(two), root=d2, baseline=load_baseline(bl))
    assert len(suppressed) == 1 and len(kept) == 1
    assert kept[0].to_finding().line == 8                      # the NEW exit survives
    # B2: a comment inserted at the top shifts every line, including the `@L4`
    # taint road inside the fund-flow message — the fingerprint must not move.
    base = UNGUARDED.read_text()
    da, a = _scan_one(tmp_path, "shift_a", base)
    db, b = _scan_one(tmp_path, "shift_b", "// shifted\n" + base)
    ff_a = [f for f in a if f.detector_name == "tainted-fund-flow"]
    ff_b = [f for f in b if f.detector_name == "tainted-fund-flow"]
    assert ff_a and ff_b and "@L" in ff_a[0].violation.pretty()
    assert fingerprints(ff_a) == fingerprints(ff_b)
    assert set(fingerprints(a)) == set(fingerprints(b))
    # The baseline file is versioned; an old-version file is loaded but warned.
    assert json.loads(bl.read_text())["version"] == FINGERPRINT_VERSION


def test_b3_a14_json_records_use_the_finding_schema_everywhere(tmp_path, capsys):
    f = tmp_path / "p.teal"
    f.write_text(_ONE_EXIT)
    assert main(["detections", str(f), "--detector", "rekey-to", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    (rec,) = doc["rekey-to"]
    assert {"rule_id", "severity", "confidence", "message", "file", "line"} <= set(rec)
    assert rec["rule_id"] == "rekey-to" and rec["line"] == 5 and rec["severity"] == "high"
    assert doc["complete"] is True
    # `all --json` carries the same record for every sec-guide detector.
    assert main(["all", str(f), "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    (rec,) = doc["detectors"]["detections/rekey-to"]
    assert rec["rule_id"] == "rekey-to" and rec["line"] == 5
    # A14: the generic serializer keeps file/line when the violation has them.
    class _V:
        file, line = "p.teal", 5
        def pretty(self):
            return "exit at p.teal:5"
    assert finding_to_dict(_V()) == {"message": "exit at p.teal:5", "line": 5, "file": "p.teal"}


def test_b4_b13_sarif_fingerprints_help_and_whole_program_results(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "p.teal").write_text(_ONE_EXIT)
    (d / "q.teal").write_text("#pragma version 8\nintcblock 1\nintcblock 2\nint 1\nreturn\n")
    res = scan(d)
    run = json.loads(render_sarif(res))["runs"][0]
    assert run["properties"]["fingerprintVersion"] == FINGERPRINT_VERSION
    for r in run["results"]:
        assert set(r["partialFingerprints"]) == {f"tealqlFingerprint/v{FINGERPRINT_VERSION}"}
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        loc = r["locations"][0]["physicalLocation"]
        if r["properties"].get("wholeProgram"):
            assert "region" not in loc                      # artifact-only location
        else:
            assert loc["region"]["startLine"] >= 1
    whole = [r for r in run["results"] if r["ruleId"] == "sec-guide/asset-close-to"]
    assert whole and all(r["properties"]["wholeProgram"] for r in whole)
    for rule in run["tool"]["driver"]["rules"]:
        assert rule["helpUri"].endswith(f"/{rule['name']}/README.md")
        assert rule["help"]["markdown"].startswith("#")
        assert not rule["fullDescription"]["text"].startswith("#")
    # B13: the multiple-constant-blocks degradation keeps its line in the
    # scan notification and the SARIF notification region.
    note = next(n for n in res.notifications if n.kind == "multiple-constant-blocks")
    assert note.line == 2 and note.to_dict()["line"] == 2
    sarif_note = next(n for n in run["invocations"][0]["toolExecutionNotifications"]
                      if n["descriptor"]["id"] == "multiple-constant-blocks")
    assert sarif_note["locations"][0]["physicalLocation"]["region"] == {"startLine": 2}


def test_b5_taint_query_and_group_taint_carry_the_envelope_and_exit_2_when_degraded(tmp_path, capsys):
    good = tmp_path / "good.teal"
    good.write_text(UNGUARDED.read_text())
    bad = tmp_path / "bad.teal"
    bad.write_text("#pragma version 8\nfrobnicate\nint 1\nreturn\n")      # unparsed span
    assert main(["taint-query", str(good), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["complete"] is True and doc["hits"] and doc["query"] == {"attack_surface": True}
    assert main(["taint-query", str(bad), "--json"]) == 2
    doc = json.loads(capsys.readouterr().out)
    assert doc["complete"] is False and doc["notifications"] and doc["hits"] == []
    assert main(["taint-query", str(bad), "--verify"]) == 2
    out = capsys.readouterr().out
    assert "[INCOMPLETE]" in out
    assert main(["group-taint", str(bad), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["complete"] is False
    assert main(["group-taint", str(good), "--json"]) in (0, 1)
    assert json.loads(capsys.readouterr().out)["complete"] is True


def test_b6_b10_inline_directives_accept_printed_spelling_and_prologue_lines(tmp_path, caplog):
    d = tmp_path / "s"
    d.mkdir()
    (d / "prefix.teal").write_text("#pragma version 8\nint 1\nreturn // tealql-ignore: sec-guide/rekey-to\n")
    (d / "spaces.teal").write_text("#pragma version 8\nint 1\nreturn // tealql-ignore: rekey-to fee-validation\n")
    (d / "typo.teal").write_text("#pragma version 8\nint 1\nreturn // tealql-ignore: rekye-to\n")
    # B10: a whole-program finding (asset-close-to) suppressed from a comment line
    # in the prologue, not only from the #pragma line.
    (d / "whole.teal").write_text("#pragma version 8\n// tealql-ignore: asset-close-to\nint 1\nreturn\n")
    kept, suppressed = partition(list(scan(d)), root=d)
    by = {}
    for f in kept:
        by.setdefault(str(f.rel_path), set()).add(f.detector_name)
    sup = {}
    for f in suppressed:
        sup.setdefault(str(f.rel_path), set()).add(f.detector_name)
    assert "rekey-to" in sup["prefix.teal"] and "rekey-to" not in by["prefix.teal"]
    assert {"rekey-to", "fee-validation"} <= sup["spaces.teal"]
    assert "rekey-to" in by["typo.teal"]                        # a typo suppresses nothing...
    assert any("rekye-to" in r.message for r in caplog.records)  # ...and is warned about
    assert "asset-close-to" in sup["whole.teal"] and "asset-close-to" not in by["whole.teal"]
    assert "asset-close-to" in by["prefix.teal"]                 # a line directive never covers it


def test_b8_b9_from_source_wildcard_and_ambiguous_basename(tmp_path, capsys):
    prog = ("#pragma version 8\n// {f}:5\nitxn_begin\nint pay\nitxn_field TypeEnum\n"
            "txna ApplicationArgs 0\nitxn_field Receiver\nitxn_submit\nint 1\nreturn\n")
    d = tmp_path / "identity"
    d.mkdir()
    (d / "a.teal").write_text(prog.format(f="a/contract.py"))
    (d / "b.teal").write_text(prog.format(f="b/contract.py"))
    # B8: `[FILE:]LINE` without FILE means every mapped source file.
    assert main(["taint-query", str(d), "--from-src", "5", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert {h["file"] for h in doc["hits"]} == {"a.teal", "b.teal"}
    # B9: a basename naming two distinct source files is ambiguous -> exit 2.
    assert main(["taint-query", str(d), "--from-src", "contract.py:5", "--json"]) == 2
    assert "ambiguous" in capsys.readouterr().err
    assert main(["taint-query", str(d), "--from-src", "a/contract.py:5", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert {h["file"] for h in doc["hits"]} == {"a.teal"}


def test_b11_missing_baseline_path_is_an_error_not_an_empty_baseline(tmp_path, capsys):
    d = tmp_path / "s"
    d.mkdir()
    (d / "p.teal").write_text(_ONE_EXIT)
    assert main(["detections-scan", str(d), "--baseline", str(tmp_path / "nope.json")]) == 2
    assert "does not exist" in capsys.readouterr().err
    bl = tmp_path / "bl.json"
    assert main(["detections-scan", str(d), "--update-baseline", str(bl)]) == 0
    capsys.readouterr()
    assert main(["detections-scan", str(d), "--baseline", str(bl)]) == 0


def test_a15_detections_all_mode_auto_filters_per_program(tmp_path, capsys, caplog):
    app = tmp_path / "app.teal"
    app.write_text("#pragma version 8\nbyte \"k\"\napp_global_get\npop\nint 1\nreturn\n")
    lsig = tmp_path / "lsig.teal"
    lsig.write_text(_ONE_EXIT)
    assert main(["detections", str(app), "--all", "--mode", "auto", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["rekey-to"] == [] and doc["is-updatable"]          # logicsig-only detector skipped
    assert main(["detections", str(lsig), "--all", "--mode", "auto", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["rekey-to"] and doc["is-updatable"] == []           # app-only detector skipped
    # Unfiltered remains the default, but says so.
    assert main(["detections", str(app), "--all", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["rekey-to"], "unfiltered --all still runs the logicsig detectors"
    assert any("UNFILTERED" in r.message for r in caplog.records)


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_degraded_scan_formats_carry_line_in_notifications(tmp_path, capsys, fmt):
    d = tmp_path / "s"
    d.mkdir()
    (d / "q.teal").write_text("#pragma version 8\nintcblock 1\nintcblock 2\nint 1\nreturn\n")
    assert main(["detections-scan", str(d), "--format", fmt]) == 2
    out = capsys.readouterr().out
    assert "multiple-constant-blocks" in out
    if fmt == "json":
        note = next(n for n in json.loads(out)["notifications"] if n["kind"] == "multiple-constant-blocks")
        assert note["line"] == 2
