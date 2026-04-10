/**
 * @name Unprotected Deletable Application
 * @description Detects stateful TEAL contracts that can be deleted AND lack
 *              sender == creator access control on the delete path. Anyone can
 *              delete the application, permanently locking all held funds.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/unprotected-deletable
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
  approvalExitUnguardedForAction(approvalBB, onCompletionDeleteApplication()) and
  not senderCreatorGuardDominates(approvalBB)
select prog,
  "Application is deletable by anyone: no sender == creator check guards the approval path for DeleteApplication."
