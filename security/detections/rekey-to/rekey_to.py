"""sec-guide/rekey-to: path-aware missing-RekeyTo detector.

Mirrors ``rekeyTo.ql`` + the ``approvalExitProtectedForField`` / ``isProtectedBB``
chain in ``SecGuideCommon.qll``. For each approval exit, checks that
every CFG path from any program entry to the exit crosses at least one
BB containing a comparison receiving flow from ``txn RekeyTo`` whose
result reaches enforcement (``assert`` / ``bnz`` to ``err`` / ``bz`` to
``err``). Per-exit alerts — partially-guarded contracts produce one
alert per unprotected exit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import BasicBlock, SSAProgram
from tealtools.detections import common


@dataclass
class RekeyToViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a RekeyTo check — an attacker can rekey the account."
        )

    def __repr__(self) -> str:
        return f"RekeyToViolation({self.pretty()})"


class RekeyToDetector:
    name = "sec-guide/rekey-to"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[RekeyToViolation]:
        out: list[RekeyToViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_field(
                self.prog, exit_bb, "RekeyTo", file=self.file,
            ):
                out.append(RekeyToViolation(exit_bb))
        return out
