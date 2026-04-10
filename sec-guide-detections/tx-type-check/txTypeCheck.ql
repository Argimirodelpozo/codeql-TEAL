/**
 * @name Missing Transaction Type Restriction
 * @description Detects contracts (especially LogicSigs) that do not restrict the
 *              transaction type. Failing to restrict the transaction type allows
 *              attackers to submit unintended transaction types (e.g., ApplicationCall
 *              instead of Payment) to bypass business logic.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/tx-type-check
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from Program prog
where
  not txnFieldValidatedOnAllPaths("TypeEnum") and
  not txnFieldValidatedOnAllPaths("Type")
select prog,
  "Contract does not restrict the transaction type — any transaction type is accepted, allowing unintended operations."
