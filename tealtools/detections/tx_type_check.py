"""sec-guide/tx-type-check: missing transaction-type restriction (path-aware).

Per-approval-exit: each exit must be reachable only along CFG paths
that cross a BB where *either* ``txn TypeEnum`` or ``txn Type`` flows
into a comparison whose result reaches enforcement. The disjunction
matches QL's ``txTypeCheck``: validating either field counts as
restricting the transaction type.

Was: dominance-based shared base (``_FieldValidatedDetector``), which
required a *single* comparison BB to dominate every approval exit —
sound but over-conservative on dispatch chains where different
methods validate the field in their own branches.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class TxTypeCheckViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a txn Type / TypeEnum check — "
            "any transaction type is accepted."
        )

    def __repr__(self) -> str:
        return f"TxTypeCheckViolation({self.pretty()})"


class TxTypeCheckDetector:
    name = "sec-guide/tx-type-check"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[TxTypeCheckViolation]:
        out: list[TxTypeCheckViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_any_txn_field(
                self.prog, exit_bb, ["TypeEnum", "Type"], file=self.file,
            ):
                out.append(TxTypeCheckViolation(exit_bb))
        return out
