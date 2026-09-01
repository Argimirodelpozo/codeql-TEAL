"""sec-guide/asset-id-validation: a program that reads any asset-transfer field
but has an approval exit reachable without an ENFORCED ``XferAsset`` comparison,
so an attacker substitutes a worthless token for the intended asset.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.security._approval_exit import _ApprovalExitViolation, _ApprovalExitProtectedDetector
from tealql.security._program_shape import gtxn_field_reads, txn_field_reads
from tealql.tealtools.language.avm import ASSET_TRANSFER_FIELDS as _ASSET_TRANSFER_FIELDS


def _handles_asset_transfer(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    for field in _ASSET_TRANSFER_FIELDS:
        if txn_field_reads(prog, field, file=file):
            return True
        if gtxn_field_reads(prog, field, file=file):
            return True
    return False


class AssetIdValidationViolation(_ApprovalExitViolation):
    message = ('handles asset transfers but is reachable without an XferAsset check — attackers can substitute worthless tokens for the intended asset.')


class AssetIdValidationDetector(_ApprovalExitProtectedDetector):
    severity = "high"
    name = "sec-guide/asset-id-validation"
    field = "XferAsset"
    # An unpinned XferAsset lets the axfer the logicsig approves move the WRONG
    # asset — a delegated-logicsig concern.
    applies_to = frozenset({"logicsig"})
    violation_cls = AssetIdValidationViolation
    # The transfer is usually a SIBLING axfer, so the pin lives on
    # `gtxn N XferAsset` rather than `txn XferAsset`; seed both.
    seed_gtxn = True

    def applies(self) -> bool:
        return _handles_asset_transfer(self.prog, file=self.file)
