/**
 * @name Updatable Application
 * @description Detects TEAL contracts that allow UpdateApplication.
 *              A contract is updatable if OnCompletion == 4 (UpdateApplication)
 *              can reach an approval exit without being guarded by a check.
 *              Uses CFG and dominance analysis for accurate detection.
 * @kind problem
 * @severity high
 * @id teal/is-updatable
 * @tags security
 */

import codeql.teal.ast.AST
import codeql.teal.cfg.BasicBlocks
import OnCompletionGuards

/**
 * Flag if there exists an approval exit that is NOT guarded against
 * UpdateApplication (OnCompletion == 4).
 *
 * CFG/dominance logic: We find approval exits (blocks ending in return that
 * may approve). For each, we check if an OnCompletion == 4 guard controls it.
 * The guard must exist and the "non-equality" branch (reject path) must
 * dominate the path to approval — so we only approve when OnCompletion != 4.
 */
from Program prog, BasicBlock approvalBB
where
  approvalBB = approvalExit() and
  approvalBB.getFirstNode().getAstNode().getProgram() = prog and
  approvalExitUnguardedForAction(approvalBB, onCompletionUpdateApplication())
select prog,
  "Application may be updatable: OnCompletion == UpdateApplication can reach an approval exit without a guard."
