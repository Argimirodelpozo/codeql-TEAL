/**
 * @name Unprotected Updatable Application
 * @description Detects stateful TEAL contracts that can be updated AND lack
 *              sender == creator access control on the update path. Anyone can
 *              replace the contract code with a malicious version, stealing all funds.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/unprotected-updatable
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.guards.OnCompletionGuards
import SecGuideCommon

from Program prog, BasicBlock approvalBB
where
  approvalBB = approvalExit() and
  approvalBB.getFirstNode().getAstNode().getProgram() = prog and
  approvalExitUnguardedForAction(approvalBB, onCompletionUpdateApplication()) and
  not senderCreatorGuardDominates(approvalBB)
select prog,
  "Application is updatable by anyone: no sender == creator check guards the approval path for UpdateApplication."
