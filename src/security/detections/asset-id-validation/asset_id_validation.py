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

from tealtools.ssa import BasicBlock, SSAProgram
from tealtools.detections import common


_ASSET_TRANSFER_FIELDS = ("AssetAmount", "AssetReceiver", "AssetSender")


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


class AssetIdValidationDetector:
    name = "sec-guide/asset-id-validation"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[AssetIdValidationViolation]:
        if not _handles_asset_transfer(self.prog, file=self.file):
            return []
        out: list[AssetIdValidationViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_field(
                self.prog, exit_bb, "XferAsset", file=self.file,
            ):
                out.append(AssetIdValidationViolation(exit_bb))
        return out
