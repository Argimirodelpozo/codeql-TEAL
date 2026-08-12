"""The canonical fund-flow policy is representation-independent to callers.

Its implementation uses lifted pre-IR because that is where call boundaries and
guard dominance are precise. The former SSA implementation and ``ir-*`` alias no
longer exist, and lift failure is reported as incomplete instead of falling back.
"""
from pathlib import Path

from tealql.security import DETECTORS
from tealql.tealtools.ssa import SSAProgram

CASES = Path(__file__).resolve().parent / "benchmark" / "tainted-fund-flow"


def _detect(path: Path):
    return DETECTORS["tainted-fund-flow"](SSAProgram(str(path))).detect()


def test_canonical_detector_clears_owner_guard_across_callsub():
    case = CASES / "safe" / "owner_guard_across_callsub.teal"
    assert _detect(case) == []


def test_representation_prefixed_alias_is_removed():
    assert "ir-tainted-fund-flow" not in DETECTORS


def test_lift_failure_is_visible_and_never_changes_detector_semantics(monkeypatch):
    import tealql.tealtools.lift as lift_layer

    monkeypatch.setattr(lift_layer, "build_lifter", lambda prog, file=None: None)
    case = CASES / "vuln" / "unguarded_receiver.teal"
    detector = DETECTORS["tainted-fund-flow"](SSAProgram(str(case)))

    assert detector.detect() == []
    assert "did NOT run" in detector.degraded
    assert "fallback" not in detector.degraded
