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

from typing import Optional

from tealtools.ssa import SSAProgram, SSAVar
from security import common
from security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)


_CMP_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
})


class TimelockUpgradeViolation(_ExitBBViolation):
    headline = "Application allows creator updates"
    joiner = " without a timelock delay — "
    detail = "users cannot review code changes before they take effect."


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


class TimelockUpgradeDetector(_ApprovalActionGuardDetector):
    name = "sec-guide/timelock-upgrade"
    action = common.ONC_UPDATE_APPLICATION
    creator_guard = "require_present"  # only a creator-only upgrade is in scope
    violation_cls = TimelockUpgradeViolation

    def applies(self) -> bool:
        return not _has_timestamp_check(self.prog, self.file)
