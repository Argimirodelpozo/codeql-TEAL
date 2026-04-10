/**
 * @name Delete Without Balance Check
 * @description Detects contracts that handle DeleteApplication without verifying
 *              that the application balance equals the minimum balance. Deleting a
 *              contract while it holds ALGO or ASAs (including box MBR) locks those
 *              funds permanently, as the application address becomes inaccessible.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/delete-funds-check
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

/**
 * Holds when the program uses both `balance` and `min_balance` opcodes,
 * indicating a balance vs min-balance comparison.
 */
predicate hasBalanceMinBalanceCheck() {
  exists(BalanceOpcode bal, MinBalanceOpcode minBal |
    bal.getProgram() = minBal.getProgram()
  )
}

from Program prog, BasicBlock approvalBB
where
  approvalBB = approvalExit() and
  approvalBB.getFirstNode().getAstNode().getProgram() = prog and
  approvalExitUnguardedForAction(approvalBB, onCompletionDeleteApplication()) and
  not hasBalanceMinBalanceCheck()
select prog,
  "Application handles DeleteApplication without checking that balance == min_balance — funds may be locked permanently on deletion."
