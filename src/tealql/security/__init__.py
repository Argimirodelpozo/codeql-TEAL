"""Algorand-security-guide detection registry.

Detector classes live at ``detections/<kebab>/<snake>.py`` so each detection
directory is self-contained (detector, ``.teal`` fixtures, ``.expected`` output).
:data:`DETECTORS` is populated by AUTO-DISCOVERY: each name in
:data:`_DETECTION_ORDER` is importlib-loaded and scanned for the one public
``*Detector`` class it DEFINES (re-exports have a different ``__module__``) plus
an optional paired ``*Violation``. Adding a detector = write the module, add the
kebab name to the order tuple. Discovery fails LOUD in both drift directions.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_DETECTIONS_ROOT = Path(__file__).resolve().parent / "detections"


#: Curated registry order — the ONLY per-detector line to touch when adding one.
#: It drives scan/``all`` output order and the SARIF rule indices, so it stays
#: explicit rather than alphabetized.
_DETECTION_ORDER: tuple[str, ...] = (
    "abi-method-selector",
    "arbitrary-inner-appcall",
    "arbitrary-inner-asset",
    "tainted-asset-admin",
    "tainted-state-write",
    "tainted-log",
    "tainted-freeze",
    "tainted-fee",
    "asset-close-to",
    "asset-id-validation",
    "box-key",
    "close-remainder-to",
    "constant-condition",
    "delete-funds-check",
    "fee-validation",
    "group-size-check",
    "hardcoded-min-balance",
    "inner-txn-close-rekey",
    "inner-txn-fee",
    "is-deletable",
    "is-updatable",
    "lease-validation",
    "rekey-to",
    "timelock-upgrade",
    "tainted-fund-flow",
    "partial-tainted-fund-flow",
    "tx-type-check",
    "unprotected-deletable",
    "unprotected-updatable",
    "unvalidated-group-sibling",
    "unsafe-division-order",
    "unsafe-lsig-args",
)


def _load_detector_module(kebab: str, snake: str) -> Any:
    """Importlib-load ``detections/<kebab>/<snake>.py`` under the canonical name
    ``tealql.security.detections.<snake>``, so a normal import of it resolves."""
    path = _DETECTIONS_ROOT / kebab / f"{snake}.py"
    if not path.exists():
        raise ImportError(
            f"detection module missing: {path} "
            f"(every entry in _DETECTION_ORDER must have a matching .py file)"
        )
    qualified_name = f"tealql.security.detections.{snake}"
    if qualified_name in sys.modules:
        return sys.modules[qualified_name]
    spec = importlib.util.spec_from_file_location(qualified_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified_name] = module
    spec.loader.exec_module(module)
    return module


def _in_module_classes(module: Any, suffix: str) -> list[str]:
    """Public classes DEFINED in ``module`` (not re-exports) named ``*suffix``."""
    return sorted(
        n for n in vars(module)
        if n.endswith(suffix) and not n.startswith("_")
        and isinstance(getattr(module, n), type)
        and getattr(module, n).__module__ == module.__name__
    )


# Drift check 1: every detections/ dir must be registered — a dropped-in detector
# that silently never runs is the failure mode auto-discovery exists to prevent.
_on_disk = {
    d.name for d in _DETECTIONS_ROOT.iterdir()
    if d.is_dir() and not d.name.startswith(("_", "."))
}
_unregistered = _on_disk - set(_DETECTION_ORDER)
if _unregistered:
    raise ImportError(
        f"detections/ dirs not in _DETECTION_ORDER: {sorted(_unregistered)} "
        "(add each to the order tuple — that is the one manual step)")

DETECTORS: dict[str, Any] = {}
for _kebab in _DETECTION_ORDER:
    _snake = _kebab.replace("-", "_")
    _module = _load_detector_module(_kebab, _snake)   # drift check 2: missing module raises
    _dets = _in_module_classes(_module, "Detector")
    if len(_dets) != 1:
        raise ImportError(
            f"detections/{_kebab}/{_snake}.py must define exactly ONE public "
            f"*Detector class (found {_dets or 'none'})")
    _viols = _in_module_classes(_module, "Violation")
    if len(_viols) > 1:
        raise ImportError(
            f"detections/{_kebab}/{_snake}.py defines several *Violation "
            f"classes ({_viols}) — keep one paired violation (or none, for "
            "taint-framework detectors)")
    _det_cls = getattr(_module, _dets[0])
    DETECTORS[_kebab] = _det_cls

# HAZARD: the scanner filters by `mode not in applies_to`, so an unknown mode
# (e.g. "lsig" for "logicsig") silently disables the detector. Fail fast here.
from .config import VALID_MODES as _VALID_MODES  # noqa: E402
for _kebab, _det_cls in DETECTORS.items():
    _applies = getattr(_det_cls, "applies_to", None)
    if _applies is not None and not set(_applies) <= set(_VALID_MODES):
        raise ValueError(
            f"detector {_kebab!r} declares applies_to={set(_applies)} with "
            f"mode(s) outside VALID_MODES={_VALID_MODES}"
        )


# LAST: xcontract needs the detector registry to be populated.
from . import xcontract  # noqa: E402


# --- detector severity ------------------------------------------------------
#
# ``"informational"`` reports a PROPERTY ("this app is deletable"), usually
# intentional, not a finding to fix. Declared with a ``severity`` class
# attribute; a VIOLATION's own ``severity`` takes precedence over it.
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "informational")
DEFAULT_SEVERITY = "medium"


def severity_of(detector_name: str) -> str:
    """A detector's severity by kebab-case name (default ``"medium"``)."""
    cls = DETECTORS.get(detector_name)
    return getattr(cls, "severity", DEFAULT_SEVERITY) if cls is not None else DEFAULT_SEVERITY


# --- detector confidence ----------------------------------------------------
#
# How sure a finding is a TRUE positive, independent of how bad it is if real
# (that's severity). Default ``"high"`` — the dominance/flow-proven detectors are
# low-FP by construction; lower it on heuristic ones so triage can sort by trust.
CONFIDENCE_LEVELS = ("high", "medium", "low")
DEFAULT_CONFIDENCE = "high"


def confidence_of(detector_name: str) -> str:
    """A detector's confidence by kebab-case name (default ``"high"``)."""
    cls = DETECTORS.get(detector_name)
    return getattr(cls, "confidence", DEFAULT_CONFIDENCE) if cls is not None else DEFAULT_CONFIDENCE


__all__ = [
    "DETECTORS",
    "xcontract",
    "SEVERITY_LEVELS",
    "DEFAULT_SEVERITY",
    "severity_of",
    "CONFIDENCE_LEVELS",
    "DEFAULT_CONFIDENCE",
    "confidence_of",
]
