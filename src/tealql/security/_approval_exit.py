"""Shared base for the approval-exit field-protection detector family —
rekey-to, fee-validation, lease-validation, asset-id-validation.

Each flags every approving exit reachable without a check of a given txn field
(via :func:`common.approval_exit_protected_for_field`). The constructor and the
``detect()`` loop are identical; a subclass sets ``name`` + ``field`` +
``violation_cls`` (and may override :meth:`applies` for a precondition, as
asset-id-validation does — it only runs on programs that handle asset transfers).

The per-detector ``Violation`` dataclass stays in its own module: the registry
(:data:`tealql.security._DETECTION_SPECS`) resolves it by name, and each
carries a bespoke message.
"""
from __future__ import annotations

from typing import ClassVar, Optional

from tealql.tealtools.ssa import SSAProgram
from . import common


class _ApprovalExitProtectedDetector:
    """Subclasses set ``name``, ``field`` (the txn field that must be checked),
    and ``violation_cls`` (the named per-detector dataclass, called with the
    unprotected exit BB)."""

    name: ClassVar[str]
    field: ClassVar[str]
    violation_cls: ClassVar[type]
    # Detectors whose field is checked on a SIBLING group txn (asset-id-validation)
    # set this so a `gtxn N FIELD` guard counts; default keeps app-call scope.
    seed_gtxn: ClassVar[bool] = False

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def applies(self) -> bool:
        """Precondition gate — default always-on; override for a detector that
        only applies to certain programs (asset-id-validation)."""
        return True

    def detect(self) -> list:
        if not self.applies():
            return []
        out = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_field(
                self.prog, exit_bb, self.field, file=self.file,
                include_gtxn=self.seed_gtxn,
            ):
                out.append(self.violation_cls(exit_bb))
        return out
