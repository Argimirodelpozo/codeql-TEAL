/**
 * @name Missing RekeyTo Validation
 * @description Detects contracts that do not validate the RekeyTo transaction
 *              field against ZeroAddress. Without this check, an attacker can
 *              permanently transfer signing authority to their own address,
 *              compromising the escrow or delegator's account.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/rekey-to
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from Program prog
where
  not txnFieldValidatedOnAllPaths("RekeyTo")
select prog,
  "Contract does not validate txn RekeyTo — an attacker can rekey the account to themselves, gaining full control."
