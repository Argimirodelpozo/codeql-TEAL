/**
 * @name Missing AssetCloseTo Validation
 * @description Detects contracts that do not validate the AssetCloseTo transaction
 *              field. The AssetCloseTo field drains all units of a specific asset
 *              from an account. Omitting this check in asset transfer validation
 *              allows complete asset drainage.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/asset-close-to
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from Program prog
where
  not txnFieldIsChecked("AssetCloseTo")
select prog,
  "Contract does not validate txn AssetCloseTo — all asset units can be drained from the account."
