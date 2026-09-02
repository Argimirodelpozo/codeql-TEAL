"""sec-guide/timelock-upgrade: an approval exit reachable with ``OnCompletion ==
UpdateApplication``, creator-guarded (so the upgrade is intentional), but with no
genuine timelock on ITS paths — users cannot review code before it takes effect.
"""
from __future__ import annotations

from tealql.tealtools.ssa import BasicBlock
from tealql.security._action_guards import ONC_UPDATE_APPLICATION
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)
from tealql.security._field_protection import _approval_exit_protected_for_seeds
from tealql.security._program_shape import global_field_reads, ssavar_outputs


class TimelockUpgradeViolation(_ExitBBViolation):
    headline = "Application allows creator updates"
    joiner = " without a timelock delay — "
    detail = "users cannot review code changes before they take effect."


class TimelockUpgradeDetector(_ApprovalActionGuardDetector):
    severity = "medium"
    name = "sec-guide/timelock-upgrade"
    action = ONC_UPDATE_APPLICATION
    creator_guard = "require_present"  # only a creator-only upgrade is in scope
    violation_cls = TimelockUpgradeViolation

    def exit_protected(self, exit_bb: BasicBlock) -> bool:
        """A genuine timelock ON THIS EXIT'S PATHS: every entry path crosses a
        block ENFORCING a comparison that consumes a ``global LatestTimestamp``
        read (the shared per-exit must-cross core).

        HAZARD: opcode PRESENCE is not enough — a timestamp that is only stored
        or logged enforces no delay, and a comparison whose result is dropped
        enforces nothing (both stay findings). Nor is program-wide existence: an
        auction deadline in the NoOp arm is a real, enforced timestamp check that
        delays NOTHING about the Update arm, and the former whole-program
        ``applies()`` let it silence the finding on exactly the DeFi contracts
        most likely to carry timestamps (finding 1.6)."""
        seeds = ssavar_outputs(
            global_field_reads(self.prog, "LatestTimestamp", file=self.file)
        )
        return _approval_exit_protected_for_seeds(
            self.prog, exit_bb, seeds, file=self.file)
