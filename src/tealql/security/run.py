"""Combined detector run for the CLI's ``all`` command: tealtools core detectors
PLUS the sec-guide ones, injected as ``extra_detectors`` adapters so the
dependency stays one-directional (security -> tealtools, never the reverse).
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.reporting.registry import (
    Detector, _FnDetector,
    run_all_dict as _core_run_all_dict,
    run_all_findings as _core_run_all_findings,
)
from . import DETECTORS
from .scan import default_detection_names

# Report-style / lint-noise on typical contracts, so kept OUT of the ``tealql
# all`` overview — run via ``tealql detections --detector NAME``.
_ON_DEMAND_ONLY = frozenset({
    "abi-method-selector",
    "constant-condition",
})

# HAZARD: DERIVED from the registry, never enumerated. A hand-written inclusion
# list silently excludes every detector registered after it was written.
_SECGUIDE_NAMES = tuple(
    n for n in default_detection_names() if n not in _ON_DEMAND_ONLY
)


def _secguide_detector(short_name: str, notes: "list | None" = None) -> Detector:
    """A ``Detector`` adapter around the registered class for ``short_name``.
    App-vs-logicsig scope is a DECLARED concern of the scanner, not inferred here,
    so ``tealql all`` runs every detector.

    When ``notes`` is given, a detector that reports itself ``degraded`` (an
    ir-* one whose contract did not lift) records there. That capture has to
    happen HERE, in the adapter that owns the instance: the tealtools runner
    only ever sees the returned findings, and teaching it about degradation
    would point the dependency arrow backwards."""
    def _run(prog: SSAProgram):
        det = DETECTORS[short_name](prog)
        out = det.detect()
        degraded = getattr(det, "degraded", None)
        if degraded and notes is not None:
            notes.append((short_name, degraded))
        return out
    return _FnDetector(f"detections/{short_name}", _run)


SECGUIDE_DETECTORS: list[Detector] = [_secguide_detector(n) for n in _SECGUIDE_NAMES]


def _collecting() -> "tuple[list, list]":
    """Fresh adapters bound to a fresh notes list — never the module-level
    ``SECGUIDE_DETECTORS``, which would accumulate across calls."""
    notes: list = []
    return [_secguide_detector(n, notes) for n in _SECGUIDE_NAMES], notes


def _degradation_text(notes: list) -> str:
    if not notes:
        return ""
    lines = "\n".join(f"  [DEGRADED] detections/{n}: {msg}" for n, msg in notes)
    return (f"\n\n{len(notes)} analysis degradation(s) — results are "
            f"INCOMPLETE:\n{lines}")


def run_all(prog: SSAProgram) -> str:
    """tealtools core detectors + reports + the sec-guide detectors, as text."""
    return run_all_findings(prog)[0]


def run_all_findings(prog: SSAProgram) -> tuple[str, int]:
    """:func:`run_all` text plus the total finding count (for exit codes).

    Degradation is appended to the TEXT but deliberately not to the COUNT: a
    detector that could not run has not found anything, and inflating the count
    would change the exit code and read as a vulnerability."""
    dets, notes = _collecting()
    text, n = _core_run_all_findings(prog, extra_detectors=dets)
    return text + _degradation_text(notes), n


def run_all_dict(prog: SSAProgram) -> dict:
    """Structured-dict variant of :func:`run_all`.

    ``notifications`` is always present, so a consumer can distinguish "ran and
    found nothing" from "never ran" without version-sniffing the key."""
    dets, notes = _collecting()
    out = _core_run_all_dict(prog, extra_detectors=dets)
    out["notifications"] = [
        {"kind": "detector-degraded", "detector": n, "message": msg}
        for n, msg in notes
    ]
    return out
