/**
 * @name Missing Fee Validation
 * @description Detects contracts that do not bound the transaction fee.
 *              Without fee validation, attackers can repeatedly submit
 *              transactions with inflated fees to drain an account's ALGO
 *              balance through accumulated fee extraction.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/fee-validation
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from Program prog
where
  not hasFeeCheck()
select prog,
  "Contract does not validate txn Fee — an attacker can set excessively high fees to drain the account."
