/**
 * @name Missing Txn Fee Validation
 * @description Detects TEAL contracts (LogicSigs and stateful) that do not
 *              validate txn Fee on all approval paths. Uses CFG and dominance
 *              analysis: a fee check must dominate every approval exit so no
 *              path can approve without going through fee validation.
 *              Without this, an attacker can set an excessively high fee.
 * @kind problem
 * @problem.severity high
 * @id teal/missing-fee-validation
 * @tags security
 */

import codeql.teal.ast.AST
import codeql.teal.cfg.BasicBlocks
import codeql.OnCompletionGuards
import codeql.FeeValidationGuards

/**
 * Flag programs that have at least one approval exit but no fee check
 * dominates all of them — meaning some path to approval bypasses fee validation.
 */
from Program prog, BasicBlock approvalBB
where
  approvalBB = approvalExit() and
  approvalBB.getFirstNode().getAstNode().getProgram() = prog and
  not feeCheckDominatesAllApprovalsIn(prog)
select prog,
  "Missing Txn.Fee validation: an approval path exists that is not dominated by a fee check (attacker can set an excessively high fee)."
