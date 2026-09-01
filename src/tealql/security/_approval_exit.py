"""Shared base for the approval-exit field-protection detector family (rekey-to,
fee-validation, lease-validation, asset-id-validation): flag every approving exit
reachable without a check of a given txn field.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.tealtools.ssa import BasicBlock, SSAProgram
from ._field_protection import (
    approval_exit_protected_for_field,
    approval_exit_protected_for_signed_txn_field,
)
from ._program_shape import approving_exits


@dataclass
class _ApprovalExitViolation:
    """Shared shape of the family's finding: renders
    ``Approval exit at {file}:{line} {message}``. A subclass sets ``message``.

    Eight detectors used to re-roll this byte-for-byte (with the line-anchor
    invariant comment repeated eight times); one drifting copy meant one
    detector's ``line`` silently stops mirroring ``pretty()``."""

    exit_bb: BasicBlock

    message: ClassVar[str]

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Must mirror pretty(): the exit's LAST line.
        return self.exit_bb.last_line

    def pretty(self) -> str:
        return (
            f"Approval exit at {self.exit_bb.file}:{self.exit_bb.last_line} "
            f"{self.message}"
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.pretty()})"


class _ApprovalExitProtectedDetector:
    """Subclasses set ``name``, ``field``, and ``violation_cls`` (called with the
    unprotected exit BB), and may override :meth:`applies`."""

    name: ClassVar[str]
    field: ClassVar[str]
    violation_cls: ClassVar[type]
    # Set when the field is checked on a SIBLING group txn, so a `gtxn N FIELD`
    # guard counts; the default keeps app-call scope.
    seed_gtxn: ClassVar[bool] = False
    # Delegated-LOGICSIG drain fields: the check must read the SIGNED txn's OWN
    # field, since a bare sibling `gtxn N` protects the signer from nothing.
    signed_txn: ClassVar[bool] = False

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def applies(self) -> bool:
        """Precondition gate; default always-on."""
        return True

    def detect(self) -> list:
        if not self.applies():
            return []
        out = []
        for exit_bb in sorted(
            approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if self.signed_txn:
                protected = approval_exit_protected_for_signed_txn_field(
                    self.prog, exit_bb, self.field, file=self.file)
            else:
                protected = approval_exit_protected_for_field(
                    self.prog, exit_bb, self.field, file=self.file,
                    include_gtxn=self.seed_gtxn)
            if not protected:
                out.append(self.violation_cls(exit_bb))
        return out
