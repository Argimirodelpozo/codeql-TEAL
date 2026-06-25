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
)
from . import DETECTORS

# The sec-guide detectors surfaced in ``tealql all`` (a curated subset — some
# registry entries, e.g. abi-method-selector / constant-condition /
# tainted-fund-flow, are run on demand only).
_SECGUIDE_NAMES = (
    "asset-close-to",
    "asset-id-validation",
    "box-key",
    "close-remainder-to",
    "delete-funds-check",
    "fee-validation",
    "group-size-check",
    "hardcoded-min-balance",
    "inner-txn-close-rekey",
    "inner-txn-fee",
    "is-deletable",
    "is-updatable",
    "rekey-to",
    "timelock-upgrade",
    "tx-type-check",
    "unprotected-deletable",
    "unprotected-updatable",
    "unsafe-lsig-args",
)


def _secguide_detector(short_name: str) -> Detector:
    """A ``Detector`` adapter that instantiates and runs the registered
    detector class for ``short_name`` — but only when the detector's
    ``applies_to`` matches the program's classified kind (app vs logicsig), so a
    logicsig-only detector doesn't fire on an application (and vice versa)."""
    from . import common

    def _run(prog: SSAProgram):
        cls = DETECTORS[short_name]
        if not common.program_applies_to(prog, cls):
            return []
        return cls(prog).detect()
    return _FnDetector(f"detections/{short_name}", _run)


SECGUIDE_DETECTORS: list[Detector] = [_secguide_detector(n) for n in _SECGUIDE_NAMES]


def run_all(prog: SSAProgram) -> str:
    """tealtools core detectors + reports + the sec-guide detectors, as text."""
    return _core_run_all(prog, extra_detectors=SECGUIDE_DETECTORS)


def run_all_dict(prog: SSAProgram) -> dict:
    """Structured-dict variant of :func:`run_all`."""
    return _core_run_all_dict(prog, extra_detectors=SECGUIDE_DETECTORS)
