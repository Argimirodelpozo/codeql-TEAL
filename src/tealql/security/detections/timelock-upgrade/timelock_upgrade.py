"""sec-guide/timelock-upgrade: an approval exit reachable with ``OnCompletion ==
UpdateApplication``, creator-guarded (so the upgrade is intentional), but with no
genuine timelock — users cannot review code before it takes effect.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.language.avm import CMP_OPS
from tealql.security._action_guards import ONC_UPDATE_APPLICATION
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)
from tealql.security._enforcement import enforced_op_exists
from tealql.security._program_shape import global_field_reads, ssavar_outputs
from tealql.security._value_flow import _operand_flows_from_field_var


class TimelockUpgradeViolation(_ExitBBViolation):
    headline = "Application allows creator updates"
    joiner = " without a timelock delay — "
    detail = "users cannot review code changes before they take effect."


def _has_timestamp_check(
    prog: SSAProgram, file: Optional[str] = None,
) -> bool:
    """A genuine timelock: a ``global LatestTimestamp`` value flows into a
    comparison.

    HAZARD: opcode PRESENCE is not enough. A timestamp that is only stored or
    logged (``global LatestTimestamp; app_global_put``) enforces no delay, and
    crediting it lets one dead read suppress the finding."""
    seeds = ssavar_outputs(
        global_field_reads(prog, "LatestTimestamp", file=file)
    )
    if not seeds:
        return False
    # And ENFORCED: a comparison whose result is dropped enforces no delay, so
    # one dead comparison would silence the detector.
    return enforced_op_exists(
        prog, CMP_OPS,
        lambda op: any(_operand_flows_from_field_var(prog, v, seeds)
                       for v in op.inputs),
        file=file,
    )


class TimelockUpgradeDetector(_ApprovalActionGuardDetector):
    severity = "medium"
    name = "sec-guide/timelock-upgrade"
    action = ONC_UPDATE_APPLICATION
    creator_guard = "require_present"  # only a creator-only upgrade is in scope
    violation_cls = TimelockUpgradeViolation

    def applies(self) -> bool:
        return not _has_timestamp_check(self.prog, self.file)
