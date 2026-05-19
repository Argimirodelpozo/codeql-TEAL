/**
 * @name Updatable Without Timelock
 * @description Detects contracts that allow UpdateApplication but do not implement
 *              a timelock delay pattern. Immediate contract upgrades prevent users
 *              from reviewing new code and exiting before the upgrade takes effect.
 *              A timelock pattern uses global LatestTimestamp to enforce a minimum
 *              delay between announcing an upgrade and executing it.
 * @kind problem
 * @severity medium
 * @id teal/sec-guide/timelock-upgrade
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

/**
 * Holds when the program reads `global LatestTimestamp` — a necessary
 * component of a timelock pattern.
 */
predicate hasTimestampCheck() {
  exists(GlobalOpcode g | g.getField() = "LatestTimestamp")
}

from Program prog, BasicBlock approvalBB
where
  approvalBB = approvalExit() and
  approvalBB.getFirstNode().getAstNode().getProgram() = prog and
  approvalExitUnguardedForAction(approvalBB, onCompletionUpdateApplication()) and
  senderCreatorGuardDominates(approvalBB) and
  not hasTimestampCheck()
select prog,
  "Application allows creator updates without a timelock delay — users cannot review code changes before they take effect."
