/**
 * @name Inner Transaction Non-Zero Fee
 * @description Detects inner transactions that explicitly set a non-zero fee.
 *              Inner transaction fees should always be 0; the caller covers fees
 *              via fee pooling. Explicitly setting fee to MinTxnFee or a hardcoded
 *              value allows repeated invocations to drain the application account
 *              through accumulated fees.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/inner-txn-fee
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from InnerTransactionField itxnField
where
  innerTxnSetsNonZeroFee(itxnField)
select itxnField,
  "Inner transaction sets a non-zero fee — repeated calls can drain the application account. Use fee 0 and rely on caller fee pooling."
