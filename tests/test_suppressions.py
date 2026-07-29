"""Suppressions: inline // tealql-ignore + baseline fingerprints (B2)."""
from __future__ import annotations

from pathlib import Path

from tealql.cli.main import main
from tealql.security.scan import scan
from tealql.security.suppress import (fingerprint, load_baseline, partition,
                               write_baseline)

TESTS_ROOT = Path(__file__).resolve().parent
REKEY_VULN = TESTS_ROOT / "benchmark" / "rekey-to" / "vuln"


# --- inline // tealql-ignore -------------------------------------------------


def test_inline_ignore_all_detectors(tmp_path):
    # Bare `// tealql-ignore` on a line suppresses EVERY detector anchored to
    # that line. (Whole-program findings — line=None, e.g. asset-close-to — are
    # not "on" this line, so they correctly survive; inline is line-local.)
    (tmp_path / "prog.teal").write_text(
        "#pragma version 8\nint 1\nreturn  // tealql-ignore\n")
    findings = scan(tmp_path)
    kept, suppressed = partition(findings, root=tmp_path)
    assert suppressed, "bare tealql-ignore should suppress the line-3 findings"
    # Everything anchored to line 3 is gone; only whole-program (line None) left.
    assert all(f.to_finding().line is None for f in kept), \
        {f.detector_name for f in kept}
    assert "rekey-to" in {f.detector_name for f in suppressed}


def test_inline_ignore_scoped_to_detector(tmp_path):
    (tmp_path / "prog.teal").write_text(
        "#pragma version 8\nint 1\nreturn  // tealql-ignore: rekey-to\n")
    findings = scan(tmp_path)
    kept, suppressed = partition(findings, root=tmp_path)
    kept_names = {f.detector_name for f in kept}
    sup_names = {f.detector_name for f in suppressed}
    assert "rekey-to" in sup_names          # scoped one suppressed
    assert "rekey-to" not in kept_names
    assert kept_names, "other detectors still fire (scope respected)"


def test_inline_ignore_on_line_above(tmp_path):
    # A directive on the line directly above the flagged line also counts. The
    # approval-exit findings anchor at the `return` (line 3); the directive sits
    # on the `int 1` line directly above it (line 2).
    (tmp_path / "prog.teal").write_text(
        "#pragma version 8\nint 1  // tealql-ignore: rekey-to\nreturn\n")
    findings = scan(tmp_path)
    kept, suppressed = partition(findings, root=tmp_path)
    assert "rekey-to" not in {f.detector_name for f in kept}
    assert "rekey-to" in {f.detector_name for f in suppressed}


def test_cli_inline_ignore(tmp_path, capsys):
    (tmp_path / "prog.teal").write_text(
        "#pragma version 8\nint 1\nreturn  // tealql-ignore: rekey-to\n")
    main(["detections-scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert "rekey-to" not in out


# --- baseline ----------------------------------------------------------------


def test_baseline_roundtrip(tmp_path):
    findings = scan(REKEY_VULN)
    assert findings
    bl = tmp_path / "baseline.json"
    n = write_baseline(bl, findings)
    assert n == len({fingerprint(f) for f in findings})
    loaded = load_baseline(bl)
    kept, suppressed = partition(findings, root=REKEY_VULN, baseline=loaded)
    assert kept == [], "every baselined finding should be suppressed"
    assert len(suppressed) == len(findings)


def test_baseline_lets_new_findings_through(tmp_path):
    findings = scan(REKEY_VULN)
    bl = tmp_path / "baseline.json"
    # Baseline everything EXCEPT one finding → only that one survives.
    write_baseline(bl, findings[1:])
    kept, _ = partition(findings, root=REKEY_VULN, baseline=load_baseline(bl))
    assert len(kept) == 1
    assert fingerprint(kept[0]) == fingerprint(findings[0])


def test_fingerprint_line_insensitive(tmp_path):
    # The fingerprint ignores line numbers so an edit elsewhere doesn't churn it.
    findings = scan(REKEY_VULN)
    f = findings[0]

    class _Shifted:
        detector_name = f.detector_name
        rel_path = f.rel_path

        class violation:
            @staticmethod
            def pretty():
                # same message, different line number
                import re
                return re.sub(r":\d+", ":999", f.violation.pretty())

    assert fingerprint(_Shifted) == fingerprint(f)


def test_cli_baseline_flow(tmp_path, capsys):
    bl = tmp_path / "bl.json"
    rc = main(["detections-scan", str(REKEY_VULN), "--update-baseline", str(bl)])
    assert rc == 0 and bl.exists()
    capsys.readouterr()
    rc = main(["detections-scan", str(REKEY_VULN), "--baseline", str(bl)])
    assert rc == 0, "all findings baselined → clean exit"
    assert "(no findings)" in capsys.readouterr().out
