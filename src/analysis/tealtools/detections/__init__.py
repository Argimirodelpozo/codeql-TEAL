"""Algorand-security-guide detection ports — registry.

The actual detector classes live next to their CodeQL counterparts at
``security/detections/<kebab-case-name>/<snake_case_name>.py`` so each
detection directory is fully self-contained: ``.ql`` query, ``.py``
port, ``.teal`` test fixtures, and ``.expected`` output sit together.

This package keeps the shared infrastructure here in
``analysis/tealtools/detections/`` because it's library code that both
ports and external callers consume:

  - :mod:`.common`             — approval-exit detection, OnCompletion
                                 guards, sender == creator, field-
                                 validated-on-all-paths, path-aware
                                 field-protected, inner-txn iteration.
  - :mod:`._field_validated`   — shared base for strict-dominance
                                 txn-field validation detectors.
  - :mod:`.xcontract`          — cross-contract findings driver.
  - :mod:`.scan`               — directory-walking scanner that builds
                                 per-dir DBs and runs detections on each.

The :data:`DETECTORS` map below is populated by importlib-loading each
``security/detections/<kebab>/<snake>.py`` file at import time, so adding
a new detection is a matter of dropping a file into the right directory
with a known-named exported class.

The ports preserve QL semantics — including the over-conservative
shapes (e.g. ``is-deletable`` flagging ``fixed-complex-dispatch.teal``,
the strict-dominance form of ``txnFieldValidatedOnAllPaths``). Tighter
detectors are deliberate follow-ups, not changes to these ports.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Optional

# Shared modules are imported eagerly so detector .py files can resolve
# ``from tealtools.detections.common import ...`` etc. when importlib
# pulls them in below.
from . import _field_validated, common  # noqa: F401


# Source root: this file is at <repo>/src/analysis/tealtools/detections/__init__.py,
# so parents[3] is <repo>/src — the detection .py files sit beside their
# CodeQL counterparts under src/security/detections/.
_SRC_ROOT = Path(__file__).resolve().parents[3]
_DETECTIONS_ROOT = _SRC_ROOT / "security" / "detections"


# Stable map ``"<kebab-case-short-name>" -> (snake_case_module_name,
# DetectorClassName, ViolationClassName)``. The CLI (``python -m
# tealtools detections --detector <name>``) and the test dispatch
# look up by the kebab-case key. The fourth field is the paired
# Violation class name, or ``None`` for detectors built on the taint
# framework (which emit the generic ``dataflow.Violation``).
_DETECTION_SPECS: tuple[tuple[str, str, str, "Optional[str]"], ...] = (
    ("abi-method-selector",   "abi_method_selector",   "AbiMethodSelectorDetector",   "AbiMethodSelectorViolation"),
    ("asset-close-to",        "asset_close_to",        "AssetCloseToDetector",        "AssetCloseToViolation"),
    ("asset-id-validation",   "asset_id_validation",   "AssetIdValidationDetector",   "AssetIdValidationViolation"),
    ("box-key",               "box_key",               "NonUniqueBoxKeyDetector",     None),
    ("close-remainder-to",    "close_remainder_to",    "CloseRemainderToDetector",    "CloseRemainderToViolation"),
    ("delete-funds-check",    "delete_funds_check",    "DeleteFundsCheckDetector",    "DeleteFundsCheckViolation"),
    ("fee-validation",        "fee_validation",        "FeeValidationDetector",       "FeeValidationViolation"),
    ("group-size-check",      "group_size_check",      "GroupSizeCheckDetector",      "GroupSizeCheckViolation"),
    ("hardcoded-min-balance", "hardcoded_min_balance", "HardcodedMinBalanceDetector", "HardcodedMinBalanceViolation"),
    ("inner-txn-close-rekey", "inner_txn_close_rekey", "InnerTxnCloseRekeyDetector",  "InnerTxnCloseRekeyViolation"),
    ("inner-txn-fee",         "inner_txn_fee",         "InnerTxnFeeDetector",         "InnerTxnFeeViolation"),
    ("is-deletable",          "is_deletable",          "IsDeletableDetector",         "IsDeletableViolation"),
    ("is-updatable",          "is_updatable",          "IsUpdatableDetector",         "IsUpdatableViolation"),
    ("lease-validation",      "lease_validation",      "LeaseValidationDetector",     "LeaseValidationViolation"),
    ("rekey-to",              "rekey_to",              "RekeyToDetector",             "RekeyToViolation"),
    ("timelock-upgrade",      "timelock_upgrade",      "TimelockUpgradeDetector",     "TimelockUpgradeViolation"),
    ("tx-type-check",         "tx_type_check",         "TxTypeCheckDetector",         "TxTypeCheckViolation"),
    ("unprotected-deletable", "unprotected_deletable", "UnprotectedDeletableDetector", "UnprotectedDeletableViolation"),
    ("unprotected-updatable", "unprotected_updatable", "UnprotectedUpdatableDetector", "UnprotectedUpdatableViolation"),
    ("unsafe-lsig-args",      "unsafe_lsig_args",      "UnsafeLsigArgsDetector",      "UnsafeLsigArgsViolation"),
)


def _load_detector_module(kebab: str, snake: str) -> Any:
    """Importlib-load ``security/detections/<kebab>/<snake>.py`` under the
    canonical module name ``tealtools.detections.<snake>`` so a
    ``from tealtools.detections.<snake> import ...`` line elsewhere
    in the codebase resolves through the standard import system."""
    path = _DETECTIONS_ROOT / kebab / f"{snake}.py"
    if not path.exists():
        raise ImportError(
            f"detection module missing: {path} "
            f"(every entry in _DETECTION_SPECS must have a matching .py file)"
        )
    qualified_name = f"tealtools.detections.{snake}"
    if qualified_name in sys.modules:
        return sys.modules[qualified_name]
    spec = importlib.util.spec_from_file_location(qualified_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified_name] = module
    spec.loader.exec_module(module)
    return module


DETECTORS: dict[str, Any] = {}
for _kebab, _snake, _det_cls_name, _viol_cls_name in _DETECTION_SPECS:
    _module = _load_detector_module(_kebab, _snake)
    _det_cls = getattr(_module, _det_cls_name)
    DETECTORS[_kebab] = _det_cls
    # Re-export each class at package level so ``from tealtools.detections
    # import AssetCloseToDetector`` keeps working.
    globals()[_det_cls_name] = _det_cls
    if _viol_cls_name is not None:
        globals()[_viol_cls_name] = getattr(_module, _viol_cls_name)


# xcontract is imported last because it depends on individual detector
# classes being loaded into this package's namespace already.
from . import xcontract  # noqa: E402


__all__ = [
    "DETECTORS",
    "common",
    "xcontract",
    *(det for _, _, det, _ in _DETECTION_SPECS),
    *(viol for _, _, _, viol in _DETECTION_SPECS if viol is not None),
]
