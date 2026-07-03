"""sec-guide/asset-id-validation: missing XferAsset check on asset transfers
(path-aware).

If the program reads any asset-transfer field (``AssetAmount`` /
``AssetReceiver`` / ``AssetSender`` via ``txn`` or ``gtxn``), then every
approval exit must be reachable only along CFG paths that cross a BB
where ``XferAsset`` flows into a comparison whose result reaches
enforcement.

Was: whole-program existence check (``handles asset transfer AND
not compared anywhere``), which produced false negatives whenever
the ``XferAsset`` check was on one branch and the asset-transfer
read on another, or when the check was inside a subroutine not on
every path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import BasicBlock, SSAProgram
from tealql.security import common
from tealql.security._approval_exit import _ApprovalExitProtectedDetector
from tealql.tealtools.avm import ASSET_TRANSFER_FIELDS as _ASSET_TRANSFER_FIELDS


def _handles_asset_transfer(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    for field in _ASSET_TRANSFER_FIELDS:
        if common.txn_field_reads(prog, field, file=file):
            return True
        if common.gtxn_field_reads(prog, field, file=file):
            return True
    return False


@dataclass
class AssetIdValidationViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "handles asset transfers but is reachable without an XferAsset check "
            "— attackers can substitute worthless tokens for the intended asset."
        )

    def __repr__(self) -> str:
        return f"AssetIdValidationViolation({self.pretty()})"


class AssetIdValidationDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/asset-id-validation"
    field = "XferAsset"
    # Signed-txn-field check: an unpinned XferAsset lets the axfer the
    # logicsig approves move the WRONG asset — delegated-logicsig concern.
    applies_to = frozenset({"logicsig"})
    violation_cls = AssetIdValidationViolation
    # The asset transfer is usually a SIBLING axfer, so the XferAsset pin lives on
    # `gtxn N XferAsset`, not `txn XferAsset` — seed both.
    seed_gtxn = True

    def applies(self) -> bool:
        # Only programs that actually move assets need an XferAsset check.
        return _handles_asset_transfer(self.prog, file=self.file)
