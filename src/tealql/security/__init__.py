"""Algorand-security-guide detection ports — registry.

The actual detector classes live at
``security/detections/<kebab-case-name>/<snake_case_name>.py`` so each
detection directory is fully self-contained: the ``.py`` detector,
``.teal`` test fixtures, and ``.expected`` output sit together.

This package keeps the shared infrastructure here in
``security/`` because it's library code that both
ports and external callers consume:

  - :mod:`.common`             — approval-exit detection, OnCompletion
                                 guards, sender == creator, field-
                                 validated-on-all-paths, path-aware
                                 field-protected, inner-txn iteration.
  - :mod:`._field_validated`   — shared base for strict-dominance
                                 txn-field validation detectors.
  - :mod:`.xcontract`          — cross-contract findings driver.
  - :mod:`.scan`               — directory-walking scanner that builds
                                 per-dir programs and runs detections on each.

The :data:`DETECTORS` map below is populated by AUTO-DISCOVERY: for each
kebab-case name in :data:`_DETECTION_ORDER`, the module
``detections/<kebab>/<kebab-as-snake>.py`` is importlib-loaded and scanned
for the one public ``*Detector`` class it DEFINES (re-exported base/framework
classes have a different ``__module__`` and are ignored), plus its optional
paired ``*Violation`` class (absent for detectors built on the generic taint
framework, which emit ``dataflow.Violation``). Adding a detector is: write
``detections/<kebab>/<snake>.py`` and add the kebab name to
:data:`_DETECTION_ORDER`. Discovery fails LOUD in both drift directions — a
detections/ directory missing from the order, or an order entry without its
module — and on an ambiguous module (zero or several public in-module
``*Detector`` classes).

The order tuple is the single curated source of registry order (the default
scan / ``all`` output order and the SARIF rule indices); alphabetizing it
would churn every consumer for no gain, so it stays explicit.

The detectors keep some over-conservative shapes (e.g. ``is-deletable``
flagging ``fixed-complex-dispatch.teal``, the strict-dominance form of
``txnFieldValidatedOnAllPaths``). Tighter detectors are deliberate
follow-ups, not changes to these.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

# Shared modules are imported eagerly so detector .py files can resolve
# ``from tealql.security.common import ...`` etc. when importlib
# pulls them in below.
from . import _approval_exit, _field_validated, common  # noqa: F401


# This file is <repo>/src/tealql/security/__init__.py; the detector .py bodies live in
# the sibling ``detections/`` dir, one per kebab-case subdir.
_DETECTIONS_ROOT = Path(__file__).resolve().parent / "detections"


#: The curated registry order — the ONLY per-detector line to touch when
#: adding one. Everything else (module path, class names) is discovered.
_DETECTION_ORDER: tuple[str, ...] = (
    "abi-method-selector",
    "arbitrary-inner-appcall",
    "ir-arbitrary-inner-appcall",
    "arbitrary-inner-asset",
    "ir-arbitrary-inner-asset",
    "ir-tainted-asset-admin",
    "ir-tainted-state-write",
    "ir-tainted-log",
    "ir-tainted-freeze",
    "ir-tainted-fee",
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
    "ir-tainted-fund-flow",
    "ir-partial-tainted-fund-flow",
    "tx-type-check",
    "unprotected-deletable",
    "unprotected-updatable",
    "unvalidated-group-sibling",
    "unsafe-division-order",
    "unsafe-lsig-args",
)


def _load_detector_module(kebab: str, snake: str) -> Any:
    """Importlib-load ``security/detections/<kebab>/<snake>.py`` under the
    canonical module name ``tealql.security.detections.<snake>`` so a
    ``from tealql.security.detections.<snake> import ...`` line elsewhere
    in the codebase resolves through the standard import system."""
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


# Drift check 1: every detections/ directory must be registered (a dropped-in
# detector that silently never runs is the failure mode auto-discovery exists
# to prevent).
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
    # Re-export each class at package level so ``from tealql.security
    # import AssetCloseToDetector`` keeps working.
    globals()[_dets[0]] = _det_cls
    for _v in _viols:
        globals()[_v] = getattr(_module, _v)

# Fail fast on a detector that declares an unknown contract-kind mode: the
# scanner filters by `mode not in applies_to`, so a typo (e.g. "lsig" for the
# real "logicsig") silently disables the detector on that kind with no error.
from .config import VALID_MODES as _VALID_MODES  # noqa: E402
for _kebab, _det_cls in DETECTORS.items():
    _applies = getattr(_det_cls, "applies_to", None)
    if _applies is not None and not set(_applies) <= set(_VALID_MODES):
        raise ValueError(
            f"detector {_kebab!r} declares applies_to={set(_applies)} with "
            f"mode(s) outside VALID_MODES={_VALID_MODES}"
        )


# xcontract is imported last because it depends on individual detector
# classes being loaded into this package's namespace already.
from . import xcontract  # noqa: E402


# --- detector severity ------------------------------------------------------
#
# An ``"informational"`` detector reports a PROPERTY (e.g. "this app is
# deletable") rather than a vulnerability — usually intentional, surfaced for
# awareness, not as a finding to fix. Everything else defaults to a real finding.
# A detector declares its level with a ``severity`` class attribute; a
# VIOLATION may also carry its own ``severity`` (the IR taint family grades
# per sink field — CloseRemainderTo drain is ``critical``, Amount tampering
# ``medium``), which takes precedence over the detector's class level.
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "informational")
DEFAULT_SEVERITY = "medium"


def severity_of(detector_name: str) -> str:
    """The severity level of a detector by its kebab-case name (default
    ``"medium"``). ``"informational"`` marks property-style findings (the
    ``is-deletable`` / ``is-updatable`` family) that are not vulnerabilities."""
    cls = DETECTORS.get(detector_name)
    return getattr(cls, "severity", DEFAULT_SEVERITY) if cls is not None else DEFAULT_SEVERITY


# --- detector confidence ----------------------------------------------------
#
# How sure a finding is a TRUE positive, independent of how bad it is if real
# (that's severity). A detector declares it with a ``confidence`` class
# attribute; default ``"high"`` — the ported detectors are dominance/flow-proven
# and low-FP by construction. Lower it on the heuristic ones (e.g. syntactic
# key-matching, speculative recovery) so triage can sort by trust.
CONFIDENCE_LEVELS = ("high", "medium", "low")
DEFAULT_CONFIDENCE = "high"


def confidence_of(detector_name: str) -> str:
    """The confidence level of a detector by its kebab-case name (default
    ``"high"``)."""
    cls = DETECTORS.get(detector_name)
    return getattr(cls, "confidence", DEFAULT_CONFIDENCE) if cls is not None else DEFAULT_CONFIDENCE


__all__ = [
    "DETECTORS",
    "common",
    "xcontract",
    "SEVERITY_LEVELS",
    "DEFAULT_SEVERITY",
    "severity_of",
    "CONFIDENCE_LEVELS",
    "DEFAULT_CONFIDENCE",
    "confidence_of",
    *(cls.__name__ for cls in DETECTORS.values()),
    *(n for n in list(globals()) if n.endswith("Violation") and not n.startswith("_")),
]
