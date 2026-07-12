"""`run_all_*` (the `tealql all` runner) must be crash-isolated per detector /
report, mirroring `security/scan.py`: one broken analysis on one weird contract
cannot sink the whole report. `strict=True` re-raises instead.
"""
from __future__ import annotations

import logging

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.detector import run_all_findings, run_all_dict


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
    assert "=== cost ===" in text                    # reports ran too
    assert isinstance(n, int)


def test_run_all_dict_isolates_a_crashing_detector():
    prog = _prog()
    out = run_all_dict(prog, extra_detectors=[_BoomDetector()])
    assert out["detectors"]["boom-detector"] == []   # crashed -> empty, not fatal
    assert "auth-domination" in out["detectors"]      # other detectors present
    assert "cost" in out["reports"]                   # reports present


def test_run_all_strict_reraises():
    prog = _prog()
    with pytest.raises(RecursionError, match="boom"):
        run_all_findings(prog, extra_detectors=[_BoomDetector()], strict=True)
    with pytest.raises(RecursionError, match="boom"):
        run_all_dict(prog, extra_detectors=[_BoomDetector()], strict=True)
