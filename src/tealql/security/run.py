"""Combined detector run for the CLI's ``all`` command: tealtools core detectors
PLUS the sec-guide ones, injected as ``extra_detectors`` adapters so the
dependency stays one-directional (security -> tealtools, never the reverse).
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.detector import (
    Detector, _FnDetector,
    run_all as _core_run_all,
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


def _secguide_detector(short_name: str) -> Detector:
    """A ``Detector`` adapter around the registered class for ``short_name``.
    App-vs-logicsig scope is a DECLARED concern of the scanner, not inferred here,
    so ``tealql all`` runs every detector."""
    def _run(prog: SSAProgram):
        return DETECTORS[short_name](prog).detect()
    return _FnDetector(f"detections/{short_name}", _run)


SECGUIDE_DETECTORS: list[Detector] = [_secguide_detector(n) for n in _SECGUIDE_NAMES]


def run_all(prog: SSAProgram) -> str:
    """tealtools core detectors + reports + the sec-guide detectors, as text."""
    return _core_run_all(prog, extra_detectors=SECGUIDE_DETECTORS)


def run_all_findings(prog: SSAProgram) -> tuple[str, int]:
    """:func:`run_all` text plus the total finding count (for exit codes)."""
    return _core_run_all_findings(prog, extra_detectors=SECGUIDE_DETECTORS)


def run_all_dict(prog: SSAProgram) -> dict:
    """Structured-dict variant of :func:`run_all`."""
    return _core_run_all_dict(prog, extra_detectors=SECGUIDE_DETECTORS)
