/**
 * @name Updatable Application
 * @description Detects stateful TEAL contracts that can be updated. An application
 *              is updatable if OnCompletion == UpdateApplication (4) can reach an
 *              approval exit without being blocked. If a contract allows updates,
 *              an authorized account can replace the contract code entirely.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/is-updatable
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
  approvalExitUnguardedForAction(approvalBB, onCompletionUpdateApplication())
select prog,
  "Application is updatable: OnCompletion == UpdateApplication can reach approval without a guard."
