/**
 * @name Missing Asset ID Validation
 * @description Detects contracts that handle asset transfers (checking TypeEnum
 *              for axfer or reading AssetAmount/AssetReceiver) without validating
 *              the XferAsset field against an expected asset ID. This allows
 *              attackers to substitute worthless tokens for the intended valuable asset.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/asset-id-validation
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

/**
 * Holds when the program reads an asset-related transaction field,
 * indicating it handles asset transfers.
 */
predicate handlesAssetTransfer() {
  exists(TxnOpcode txn |
    txn.getField() = "AssetAmount" or
    txn.getField() = "AssetReceiver" or
    txn.getField() = "AssetSender"
  )
  or
  exists(GtxnOpcode gtxn |
    gtxn.getField() = "AssetAmount" or
    gtxn.getField() = "AssetReceiver" or
    gtxn.getField() = "AssetSender"
  )
}

/**
 * Holds when XferAsset is checked (the asset ID is validated).
 */
predicate hasXferAssetCheck() {
  txnFieldIsChecked("XferAsset")
  or
  exists(GtxnOpcode gtxn, LogicalComparisonOp cmp, SSAVar gtxnVar |
    gtxn.getField() = "XferAsset" and
    gtxnVar = gtxn.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = gtxnVar or
      getGenerator(cmp.secondOp()) = gtxnVar
    )
  )
}

from Program prog
where
  handlesAssetTransfer() and
  not hasXferAssetCheck()
select prog,
  "Contract handles asset transfers without validating XferAsset — attackers can substitute worthless tokens for the intended asset."
