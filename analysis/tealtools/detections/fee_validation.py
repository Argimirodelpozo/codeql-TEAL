"""sec-guide/fee-validation: missing Fee check (path-aware).

Per-approval-exit: each exit must be reachable only along CFG paths
that cross a BB where ``txn Fee`` flows into a comparison whose result
reaches enforcement (``assert`` / ``bnz`` to ``err`` / ``bz`` to ``err``).
Same machinery as :mod:`tealtools.detections.rekey_to`.

Replaces the old whole-program existence check (``compared anywhere?``),
which produced false negatives on programs that validated ``Fee`` only
on one branch (``vuln_branch_skip``) or inside a subroutine never
called on every path (``vuln_subroutine_dead``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class FeeValidationViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a txn Fee check — an attacker can drain the account."
        )

    def __repr__(self) -> str:
        return f"FeeValidationViolation({self.pretty()})"


class FeeValidationDetector:
    name = "sec-guide/fee-validation"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[FeeValidationViolation]:
        out: list[FeeValidationViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_field(
                self.prog, exit_bb, "Fee", file=self.file,
            ):
                out.append(FeeValidationViolation(exit_bb))
        return out
