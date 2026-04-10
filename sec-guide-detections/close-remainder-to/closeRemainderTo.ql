/**
 * @name Missing CloseRemainderTo Validation
 * @description Detects contracts that do not validate the CloseRemainderTo
 *              transaction field. The CloseRemainderTo field drains ALL remaining
 *              ALGO from an account in a single transaction. Omitting this check
 *              allows attackers to empty escrows or delegator accounts.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/close-remainder-to
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from Program prog
where
  not txnFieldValidatedOnAllPaths("CloseRemainderTo")
select prog,
  "Contract does not validate txn CloseRemainderTo — the account's entire ALGO balance can be drained."
