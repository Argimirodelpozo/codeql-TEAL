/**
 * @name Inner Transaction Sets CloseRemainderTo or RekeyTo
 * @description Detects inner transactions that set CloseRemainderTo or RekeyTo
 *              fields. If these fields are set to user-controlled values, attackers
 *              can drain the application account or transfer its signing authority.
 *              These fields should typically be omitted entirely (defaulting to
 *              zero address).
 * @kind problem
 * @severity high
 * @id teal/sec-guide/inner-txn-close-rekey
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from InnerTransactionField itxnField, string fieldName
where
  fieldName = itxnField.getItxnField() and
  (fieldName = "CloseRemainderTo" or fieldName = "RekeyTo" or fieldName = "AssetCloseTo")
select itxnField,
  "Inner transaction sets " + fieldName + " — this can drain the application account or transfer signing authority. Omit this field entirely."
