"""Parse diagnostics + exception spine: unparseable TEAL must never be
silently dropped.

Before this layer existed, tree-sitter ``ERROR`` nodes were treated as
trivia: a garbage (or typo'd, or newer-AVM) contract parsed to an empty
program, every detector reported "(no findings)", and the CLI exited 0 —
a security scanner handing out clean bills for input it never analyzed.

Covers: the ``SSAProgram.parse_diagnostics`` surface, the CLI warning /
``--strict`` behavior and exit-code contract, scan()'s strict mode +
per-detector crash isolation, the absence-detector empty-program guard,
and the ``byte_taint`` empty-program arity regression.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from tealql.cli.main import main
from tealql.tealtools import (
    ParseDiagnostic, SSAProgram, TargetError, TargetNotFoundError,
    TealParseError, TealQLError,
)

TESTS_ROOT = Path(__file__).resolve().parent
VULN_DB = TESTS_ROOT / "tealtools" / "auth_domination" / "vuln"
REKEY_VULN_DIR = TESTS_ROOT / "benchmark" / "rekey-to" / "vuln"

GARBAGE = "complete garbage\nnothing parses here $$$\n"
PARTIAL = "#pragma version 8\nthis is not teal at all\nint 1\nreturn\n"
VALID = "#pragma version 8\n// a comment\nint 1\nreturn\n"


# ---------------------------------------------------------------------------
# Library surface: SSAProgram.parse_diagnostics
# ---------------------------------------------------------------------------


def test_garbage_source_yields_diagnostics(tmp_path):
    f = tmp_path / "prog.teal"
    f.write_text(GARBAGE)
    prog = SSAProgram(str(f))
    assert prog.parse_diagnostics
    d = prog.parse_diagnostics[0]
    assert isinstance(d, ParseDiagnostic)
    assert d.start_line == 1
    assert "garbage" in d.snippet
    assert not prog.assignments


def test_partial_source_keeps_valid_tail_and_records_drop(tmp_path):
    f = tmp_path / "prog.teal"
    f.write_text(PARTIAL)
    prog = SSAProgram(str(f))
    assert len(prog.parse_diagnostics) >= 1
    assert prog.parse_diagnostics[0].start_line == 2
    # The valid `int 1 / return` tail still analyzed.
    assert prog.assignments


def test_valid_source_has_no_diagnostics(tmp_path):
    f = tmp_path / "prog.teal"
    f.write_text(VALID)
    prog = SSAProgram(str(f))
    assert prog.parse_diagnostics == ()
    assert prog.assignments


def test_named_int_recovery_is_not_a_diagnostic(tmp_path):
    # `int pay` parses as a tree-sitter ERROR but is deliberately RECOVERED
    # as an int-push (the named-constant form); it must not be reported as
    # unparsed source.
    f = tmp_path / "prog.teal"
    f.write_text("#pragma version 8\nint pay\nint 1\nreturn\n")
    prog = SSAProgram(str(f))
    assert prog.parse_diagnostics == ()
    assert len(prog.assignments) >= 3


# ---------------------------------------------------------------------------
# Exception hierarchy (builtin compatibility preserved)
# ---------------------------------------------------------------------------


def test_error_hierarchy():
    assert issubclass(TargetError, TealQLError)
    assert issubclass(TargetError, ValueError)
    assert issubclass(TargetNotFoundError, TealQLError)
    assert issubclass(TargetNotFoundError, FileNotFoundError)
    assert issubclass(TealParseError, TealQLError)


def test_parse_error_message_carries_first_diagnostic():
    d = ParseDiagnostic("prog.teal", 3, 3, "wat")
    err = TealParseError((d,))
    assert err.diagnostics == (d,)
    assert "prog.teal:3" in str(err)


# ---------------------------------------------------------------------------
# CLI contract: warn by default, --strict → 2, clean errors (no tracebacks)
# ---------------------------------------------------------------------------


def test_cli_warns_on_partial_parse_and_continues(tmp_path, capsys):
    f = tmp_path / "prog.teal"
    f.write_text(PARTIAL)
    rc = main(["auth", str(f)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "EXCLUDED from analysis" in err
    assert "--strict" in err


def test_cli_strict_exits_two_on_partial_parse(tmp_path, capsys):
    f = tmp_path / "prog.teal"
    f.write_text(PARTIAL)
    rc = main(["auth", str(f), "--strict"])
    assert rc == 2
    assert "unparsed TEAL" in capsys.readouterr().err


def test_cli_non_teal_target_clean_error(tmp_path, capsys):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    rc = main(["auth", str(f)])
    assert rc == 2
    assert "not a .teal file" in capsys.readouterr().err


def test_cli_all_exits_one_on_findings(capsys):
    rc = main(["all", str(VULN_DB)])
    assert rc == 1
    capsys.readouterr()


def test_cli_detections_scan_strict_refuses_garbage(tmp_path, capsys):
    (tmp_path / "prog.teal").write_text(GARBAGE)
    rc = main(["detections-scan", str(tmp_path), "--strict"])
    assert rc == 2
    assert "unparsed TEAL" in capsys.readouterr().err


def test_cli_detections_scan_garbage_warns_and_reports_nothing(tmp_path, capsys):
    (tmp_path / "prog.teal").write_text(GARBAGE)
    rc = main(["detections-scan", str(tmp_path)])
    out, err = capsys.readouterr().out, capsys.readouterr().err
    assert rc == 0
    assert "(no findings)" in out


# ---------------------------------------------------------------------------
# scan(): strict mode + per-detector crash isolation
# ---------------------------------------------------------------------------


def test_scan_strict_raises_parse_error(tmp_path):
    from tealql.security.scan import scan
    (tmp_path / "prog.teal").write_text(GARBAGE)
    with pytest.raises(TealParseError):
        scan(tmp_path, strict=True)


def test_scan_survives_a_crashing_detector(monkeypatch, caplog):
    from tealql import security
    from tealql.security.scan import scan

    class _Boom:
        def __init__(self, prog, *, file=None):
            pass

        def detect(self):
            raise RuntimeError("boom")

    monkeypatch.setitem(security.DETECTORS, "boom-test", _Boom)
    with caplog.at_level(logging.ERROR, logger="tealql.security.scan"):
        findings = scan(REKEY_VULN_DIR)
    # The crash was recorded, the rest of the scan still produced findings.
    assert any("boom-test" in r.message for r in caplog.records)
    assert any(f.detector_name == "rekey-to" for f in findings)


def test_scan_strict_propagates_detector_crash(monkeypatch):
    from tealql import security
    from tealql.security.scan import scan

    class _Boom:
        def __init__(self, prog, *, file=None):
            pass

        def detect(self):
            raise RuntimeError("boom")

    monkeypatch.setitem(security.DETECTORS, "boom-test", _Boom)
    with pytest.raises(TealQLError, match="boom-test"):
        scan(REKEY_VULN_DIR, strict=True)


def test_scan_survives_a_detector_crashing_in_init(monkeypatch, caplog):
    # A detector that does its analysis in __init__ (or just crashes building)
    # must be isolated exactly like one that crashes in detect() — this is the
    # gap that let a RecursionError in one contract's path-predicate decomposition
    # abort a whole 929-contract corpus scan.
    from tealql import security
    from tealql.security.scan import scan

    class _BoomInit:
        def __init__(self, prog, *, file=None):
            raise RecursionError("boom-init")

        def detect(self):
            return []

    monkeypatch.setitem(security.DETECTORS, "boom-init-test", _BoomInit)
    with caplog.at_level(logging.ERROR, logger="tealql.security.scan"):
        findings = scan(REKEY_VULN_DIR)
    assert any("boom-init-test" in r.message for r in caplog.records)
    assert any(f.detector_name == "rekey-to" for f in findings)


def test_scan_strict_propagates_init_crash(monkeypatch):
    from tealql import security
    from tealql.security.scan import scan

    class _BoomInit:
        def __init__(self, prog, *, file=None):
            raise ValueError("boom-init")

        def detect(self):
            return []

    monkeypatch.setitem(security.DETECTORS, "boom-init-test", _BoomInit)
    with pytest.raises(TealQLError, match="boom-init-test"):
        scan(REKEY_VULN_DIR, strict=True)


# ---------------------------------------------------------------------------
# Degenerate programs: absence detectors + byte_taint arity regression
# ---------------------------------------------------------------------------


def test_absence_detectors_silent_on_empty_program():
    from tealql.security import DETECTORS
    prog = SSAProgram.from_text("// only a comment\n", name="prog.teal")
    assert not prog.assignments
    # The strict-dominance "field never validated" family must not report a
    # contract-shaped finding about a program with no instructions.
    for name in ("asset-close-to", "close-remainder-to", "tx-type-check"):
        assert DETECTORS[name](prog).detect() == [], name


def test_byte_taint_empty_program_no_crash():
    # Regression: _validated_intervals returned a bare {} (instead of a
    # 2-tuple) for a program with no entry blocks → ValueError at unpack.
    from tealql.tealtools.dataflow.byte_taint import byte_taint
    prog = SSAProgram.from_text("// nothing here\n", name="prog.teal")
    result = byte_taint(prog, validate=True)
    assert result is not None
