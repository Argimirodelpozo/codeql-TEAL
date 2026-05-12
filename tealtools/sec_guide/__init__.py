"""Sec-guide detector ports.

Each Algorand security-guide detection from
``sec-guide-detections/<name>/<name>.ql`` has a Python equivalent here
that consumes :class:`tealtools.SSAProgram` and emits one or more
``Violation`` objects via ``.detect()``. The detectors are plugged
into :data:`tealtools.detector.ALL_DETECTORS`, so they show up under
``python -m tealtools all <db>`` and can be invoked individually via
``python -m tealtools sec-guide <name> <db>``.

The ports preserve QL semantics — including the over-conservative
shapes (e.g. ``is-deletable`` flagging ``fixed-complex-dispatch.teal``,
the strict-dominance form of ``txnFieldValidatedOnAllPaths``). Tighter
detectors are deliberate follow-ups, not changes to these ports.

Modules
-------

- :mod:`.common` — shared helpers (approval-exit, OnCompletion guards,
  sender == creator, field-validated-on-all-paths, path-aware
  field-protected, inner-txn iteration).
- :mod:`.asset_close_to`, :mod:`.close_remainder_to`,
  :mod:`.tx_type_check` — strict-dominance txn-field validation.
- :mod:`.asset_id_validation`, :mod:`.fee_validation` — anywhere-checked
  txn-field validation.
- :mod:`.rekey_to` — per-exit path-aware RekeyTo protection.
- :mod:`.is_deletable`, :mod:`.is_updatable`, :mod:`.unprotected_deletable`,
  :mod:`.unprotected_updatable`, :mod:`.delete_funds_check`,
  :mod:`.timelock_upgrade` — OnCompletion-guard family.
- :mod:`.inner_txn_close_rekey`, :mod:`.inner_txn_fee` — itxn_field
  pattern matches.
- :mod:`.hardcoded_min_balance`, :mod:`.unsafe_lsig_args`,
  :mod:`.group_size_check` — direct opcode-pattern matches.
"""

from . import common
from .asset_close_to import AssetCloseToDetector, AssetCloseToViolation
from .asset_id_validation import (
    AssetIdValidationDetector,
    AssetIdValidationViolation,
)
from .close_remainder_to import (
    CloseRemainderToDetector,
    CloseRemainderToViolation,
)
from .delete_funds_check import (
    DeleteFundsCheckDetector,
    DeleteFundsCheckViolation,
)
from .fee_validation import FeeValidationDetector, FeeValidationViolation
from .group_size_check import (
    GroupSizeCheckDetector,
    GroupSizeCheckViolation,
)
from .hardcoded_min_balance import (
    HardcodedMinBalanceDetector,
    HardcodedMinBalanceViolation,
)
from .inner_txn_close_rekey import (
    InnerTxnCloseRekeyDetector,
    InnerTxnCloseRekeyViolation,
)
from .inner_txn_fee import InnerTxnFeeDetector, InnerTxnFeeViolation
from .is_deletable import IsDeletableDetector, IsDeletableViolation
from .is_updatable import IsUpdatableDetector, IsUpdatableViolation
from .rekey_to import RekeyToDetector, RekeyToViolation
from .timelock_upgrade import (
    TimelockUpgradeDetector,
    TimelockUpgradeViolation,
)
from .tx_type_check import TxTypeCheckDetector, TxTypeCheckViolation
from .unprotected_deletable import (
    UnprotectedDeletableDetector,
    UnprotectedDeletableViolation,
)
from .unprotected_updatable import (
    UnprotectedUpdatableDetector,
    UnprotectedUpdatableViolation,
)
from .unsafe_lsig_args import (
    UnsafeLsigArgsDetector,
    UnsafeLsigArgsViolation,
)


# Stable map ``"<short-name>" -> Detector class``. Used by the CLI
# (``python -m tealtools sec-guide <name>``) and the test dispatch.
DETECTORS = {
    "asset-close-to": AssetCloseToDetector,
    "asset-id-validation": AssetIdValidationDetector,
    "close-remainder-to": CloseRemainderToDetector,
    "delete-funds-check": DeleteFundsCheckDetector,
    "fee-validation": FeeValidationDetector,
    "group-size-check": GroupSizeCheckDetector,
    "hardcoded-min-balance": HardcodedMinBalanceDetector,
    "inner-txn-close-rekey": InnerTxnCloseRekeyDetector,
    "inner-txn-fee": InnerTxnFeeDetector,
    "is-deletable": IsDeletableDetector,
    "is-updatable": IsUpdatableDetector,
    "rekey-to": RekeyToDetector,
    "timelock-upgrade": TimelockUpgradeDetector,
    "tx-type-check": TxTypeCheckDetector,
    "unprotected-deletable": UnprotectedDeletableDetector,
    "unprotected-updatable": UnprotectedUpdatableDetector,
    "unsafe-lsig-args": UnsafeLsigArgsDetector,
}


from . import xcontract  # noqa: E402  (import after DETECTORS to break circular)


__all__ = [
    "DETECTORS",
    "common",
    "xcontract",
    "AssetCloseToDetector", "AssetCloseToViolation",
    "AssetIdValidationDetector", "AssetIdValidationViolation",
    "CloseRemainderToDetector", "CloseRemainderToViolation",
    "DeleteFundsCheckDetector", "DeleteFundsCheckViolation",
    "FeeValidationDetector", "FeeValidationViolation",
    "GroupSizeCheckDetector", "GroupSizeCheckViolation",
    "HardcodedMinBalanceDetector", "HardcodedMinBalanceViolation",
    "InnerTxnCloseRekeyDetector", "InnerTxnCloseRekeyViolation",
    "InnerTxnFeeDetector", "InnerTxnFeeViolation",
    "IsDeletableDetector", "IsDeletableViolation",
    "IsUpdatableDetector", "IsUpdatableViolation",
    "RekeyToDetector", "RekeyToViolation",
    "TimelockUpgradeDetector", "TimelockUpgradeViolation",
    "TxTypeCheckDetector", "TxTypeCheckViolation",
    "UnprotectedDeletableDetector", "UnprotectedDeletableViolation",
    "UnprotectedUpdatableDetector", "UnprotectedUpdatableViolation",
    "UnsafeLsigArgsDetector", "UnsafeLsigArgsViolation",
]
