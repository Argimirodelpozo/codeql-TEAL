"""sec-guide/timelock-upgrade: updatable + creator-guarded but no timelock.

Mirrors ``timelockUpgrade.ql``. Flags an approval exit that:
  - is reachable with ``OnCompletion == UpdateApplication``,
  - has a dominating ``txn Sender == global CreatorAddress`` guard
    (so the creator-only upgrade is intentional),
  - and the program does not read ``global LatestTimestamp``
    (no timelock pattern). Users can't review code before the upgrade
    takes effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..path_predicates import PathPredicateAnalysis
from ..ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class TimelockUpgradeViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        return (
            f"Application allows creator updates at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line} without a timelock delay "
            "— users cannot review code changes before they take effect."
        )

    def __repr__(self) -> str:
        return f"TimelockUpgradeViolation({self.pretty()})"


def _has_timestamp_check(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    return bool(common.global_field_reads(prog, "LatestTimestamp", file=file))


class TimelockUpgradeDetector:
    name = "sec-guide/timelock-upgrade"

    def __init__(
        self,
        prog: SSAProgram,
        *,
        path_predicates: Optional[PathPredicateAnalysis] = None,
        file: Optional[str] = None,
    ):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or PathPredicateAnalysis(prog)

    def detect(self) -> list[TimelockUpgradeViolation]:
        if _has_timestamp_check(self.prog, self.file):
            return []
        out: list[TimelockUpgradeViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, common.ONC_UPDATE_APPLICATION,
            ):
                continue
            if not common.sender_creator_guard_dominates(self.prog, self.pp, exit_bb):
                continue
            out.append(TimelockUpgradeViolation(exit_bb))
        return out
