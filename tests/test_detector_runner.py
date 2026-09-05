"""`run_all_*` (the `tealql all` runner) must be crash-isolated per detector /
report, mirroring `security/scan.py`: one broken analysis on one weird contract
cannot sink the whole report. `strict=True` re-raises instead.
"""
from __future__ import annotations

import logging

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.reporting.registry import run_all_findings, run_all_dict


def _prog():
    return SSAProgram.from_text(
        "#pragma version 8\nint 1\nreturn\n", name="t")


class _BoomDetector:
    name = "boom-detector"

    def run(self, prog):
        raise RecursionError("boom")


def test_run_all_findings_isolates_a_crashing_detector(caplog):
    prog = _prog()
    with caplog.at_level(logging.ERROR, logger="tealql.tealtools"):
        text, n = run_all_findings(prog, extra_detectors=[_BoomDetector()])
    # the crash was logged, the report still built, other sections present
    assert any("boom-detector" in r.message for r in caplog.records)
    assert "=== auth-domination ===" in text        # a real core detector ran
    assert "=== path-predicates ===" in text          # reports ran too
    assert isinstance(n, int)
    assert "[INCOMPLETE] detector boom-detector" in text
    assert "=== boom-detector ===\n(no findings)" not in text


def test_run_all_dict_isolates_a_crashing_detector():
    prog = _prog()
    out = run_all_dict(prog, extra_detectors=[_BoomDetector()])
    assert out["detectors"]["boom-detector"] == []   # crashed -> empty, not fatal
    assert "auth-domination" in out["detectors"]      # other detectors present
    assert "path-predicates" in out["reports"]        # reports present
    assert not out["complete"]
    assert out["notifications"][0]["kind"] == "detector-crashed"
    assert not out["executions"]["detector/boom-detector"]["complete"]


def test_security_adapter_preserves_crashes(monkeypatch):
    from tealql.security import run
    class Broken:
        def __init__(self, prog):
            pass
        def detect(self):
            raise RuntimeError("construction succeeded, detection failed")
    monkeypatch.setitem(run.DETECTORS, "broken", Broken)
    monkeypatch.setattr(run, "_SECGUIDE_NAMES", ("broken",))
    out = run.run_all_dict(_prog())
    assert not out["complete"]
    assert any(n["detector"] == "detections/broken" for n in out["notifications"])
    with pytest.raises(RuntimeError, match="detection failed"):
        run.run_all_dict(_prog(), strict=True)


def test_crashing_report_is_incomplete(monkeypatch):
    from tealql.tealtools.reporting import registry
    monkeypatch.setattr(registry, "ALL_REPORTS", [registry._FnReport(
        "broken", lambda _: 1 / 0, lambda _: 1 / 0)])
    out = run_all_dict(_prog())
    assert out["reports"]["broken"] == {}
    assert any(n["kind"] == "report-crashed" for n in out["notifications"])


def test_run_all_strict_reraises():
    prog = _prog()
    with pytest.raises(RecursionError, match="boom"):
        run_all_findings(prog, extra_detectors=[_BoomDetector()], strict=True)
    with pytest.raises(RecursionError, match="boom"):
        run_all_dict(prog, extra_detectors=[_BoomDetector()], strict=True)


def test_partial_input_remains_incomplete_when_detectors_finish():
    p = SSAProgram.from_text('#pragma version 13\napp_box_get extra\nint 1\nreturn', name='partial.teal', strict=False)
    out = run_all_dict(p)
    assert not out['complete'] and out['notifications']
    assert not any(e['complete'] for e in out['executions'].values())
    assert '[INCOMPLETE]' in run_all_findings(p)[0]
    from tealql.tealtools.diagnostics.errors import TealQLError
    with pytest.raises(TealQLError, match='incomplete input'):
        run_all_dict(p, strict=True)


def test_finding_renderer_failure_is_incomplete():
    class BrokenFinding:
        def pretty(self):
            raise ValueError('render failed')
    class Detector:
        name = 'broken-renderer'
        def run(self, _):
            return [BrokenFinding()]
    result, _ = run_all_findings(_prog(), extra_detectors=[Detector()])
    assert '[INCOMPLETE] detector broken-renderer' in result
