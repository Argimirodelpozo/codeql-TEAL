/**
 * @name Deletable Application
 * @description Detects stateful TEAL contracts that can be deleted. An application
 *              is deletable if OnCompletion == DeleteApplication (5) can reach an
 *              approval exit without being blocked. Deleting a contract while it
 *              holds ALGO or ASAs locks those funds permanently.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/is-deletable
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
  approvalExitUnguardedForAction(approvalBB, onCompletionDeleteApplication())
select prog,
  "Application is deletable: OnCompletion == DeleteApplication can reach approval without a guard."
