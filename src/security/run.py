"""Combined detector run for the CLI's ``all`` command: the tealtools core
analysis detectors PLUS the sec-guide detectors.

tealtools core (:mod:`tealtools.detector`) knows nothing about the security
registry; it exposes ``run_all(prog, extra_detectors=...)``. This module builds
the sec-guide detector adapters and injects them, so the dependency stays
one-directional (security -> tealtools, never the reverse).
"""
from __future__ import annotations

from tealtools.ssa import SSAProgram
from tealtools.detector import (
    Detector, _FnDetector,
    run_all as _core_run_all,
    run_all_dict as _core_run_all_dict,
    run_all_findings as _core_run_all_findings,
)
from . import DETECTORS
from .scan import default_detection_names

# Deliberately kept OUT of the ``tealql all`` overview — run on demand via
# ``tealql detections --detector NAME`` (report-style / lint-noise on typical
# contracts, per the original curation).
_ON_DEMAND_ONLY = frozenset({
    "abi-method-selector",
    "constant-condition",
})

# Everything else registered in security.DETECTORS runs, with superseded
# detectors dropped (their successors subsume them and fall back to them
# internally when the IR lift fails). Derived, not enumerated: a hand-written
# inclusion list lived here before and silently excluded every detector
# registered after it was written — the whole ir-* family never ran in
# ``tealql all``.
_SECGUIDE_NAMES = tuple(
    n for n in default_detection_names() if n not in _ON_DEMAND_ONLY
)


def _secguide_detector(short_name: str) -> Detector:
    """A ``Detector`` adapter that instantiates and runs the registered
    detector class for ``short_name``. Scope filtering (app vs logicsig) is a
    DECLARED concern — see :class:`security.config.DetectionOptions` and the
    scanner — not inferred here, so ``tealql all`` runs every detector."""
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
