"""sec-guide/timelock-upgrade: updatable + creator-guarded but no timelock.

Flags an approval exit that:
  - is reachable with ``OnCompletion == UpdateApplication``,
  - has a dominating ``txn Sender == global CreatorAddress`` guard
    (so the creator-only upgrade is intentional),
  - and the program has no genuine timelock check — a ``global
    LatestTimestamp`` value flowing into a *comparison* (against a stored
    deadline). Users can't review code before the upgrade takes effect.

The timelock recognition requires the timestamp to reach a comparison, not merely
that the ``LatestTimestamp`` opcode appears: a contract that only *records* the
current time (``global LatestTimestamp; app_global_put``) without ever comparing
it has no enforced delay, but the old opcode-presence proxy treated that read as a
timelock and suppressed the finding — a false negative.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram, SSAVar
from security import common


_CMP_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
})


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
    """A genuine timelock: a ``global LatestTimestamp`` value flows (through the
    phi / scratch / proto-frame bridge) into a comparison — not merely that the
    opcode is read. A timestamp that is only stored/logged enforces no delay."""
    seeds = {
        o for a in common.global_field_reads(prog, "LatestTimestamp", file=file)
        for o in a.outputs if isinstance(o, SSAVar)
    }
    if not seeds:
        return False
    for op in prog.assignments:
        if op.op not in _CMP_OPS or not common.file_match(op.location.file, file):
            continue
        if not any(common._operand_flows_from_field_var(prog, v, seeds)
                   for v in op.inputs):
            continue
        # The comparison must be ENFORCED — a `LatestTimestamp > deadline` whose
        # result is dropped (or sits on an unrelated branch and is never asserted)
        # enforces no delay. Without this, an attacker silences the detector with
        # one dead timestamp comparison while leaving the upgrade un-timelocked.
        if op.outputs and isinstance(op.outputs[0], SSAVar) and \
                common.def_forward_reaches_enforcement(prog, op.outputs[0]):
            return True
    return False


class TimelockUpgradeDetector:
    name = "sec-guide/timelock-upgrade"
    applies_to = frozenset({"app"})  # UpdateApplication / app lifecycle

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
