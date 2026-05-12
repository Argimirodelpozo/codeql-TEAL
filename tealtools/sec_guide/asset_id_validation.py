"""sec-guide/asset-id-validation: missing XferAsset check on asset transfers.

Mirrors ``assetIdValidation.ql``. Flags a contract that handles asset
transfers (reads ``AssetAmount`` / ``AssetReceiver`` / ``AssetSender`` via
``txn`` or ``gtxn``) without validating ``XferAsset`` against an expected
value — attackers can substitute worthless tokens for the real asset.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import SSAProgram
from . import common


_ASSET_TRANSFER_FIELDS = ("AssetAmount", "AssetReceiver", "AssetSender")


@dataclass
class AssetIdValidationViolation:
    prog: SSAProgram

    def pretty(self) -> str:
        return (
            "Contract handles asset transfers without validating XferAsset "
            "— attackers can substitute worthless tokens for the intended asset."
        )

    def __repr__(self) -> str:
        return f"AssetIdValidationViolation({self.pretty()})"


def _handles_asset_transfer(prog: SSAProgram, file: Optional[str] = None) -> bool:
    for field in _ASSET_TRANSFER_FIELDS:
        if common.txn_field_reads(prog, field, file=file):
            return True
        if common.gtxn_field_reads(prog, field, file=file):
            return True
    return False


def _has_xfer_asset_check(prog: SSAProgram, file: Optional[str] = None) -> bool:
    return common.field_compared_anywhere(
        prog, txn_field="XferAsset", gtxn_field="XferAsset", file=file,
    )


class AssetIdValidationDetector:
    name = "sec-guide/asset-id-validation"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[AssetIdValidationViolation]:
        if not _handles_asset_transfer(self.prog, self.file):
            return []
        if _has_xfer_asset_check(self.prog, self.file):
            return []
        return [AssetIdValidationViolation(self.prog)]
