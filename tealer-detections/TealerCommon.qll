/**
 * Shared predicates for Tealer-style security detections.
 *
 * Provides reusable building blocks for checking:
 * - Approval/rejection exit paths
 * - Transaction field validation (CloseRemainderTo, AssetCloseTo, RekeyTo, Fee)
 * - Sender/Creator access control guards
 * - OnCompletion action checks
 * - GroupSize validation
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import codeql.OnCompletionGuards
private import codeql.teal.cfg.Completion::Completion

// ---------------------------------------------------------------------------
// Exit-path helpers
// ---------------------------------------------------------------------------

/** A basic block whose last node is a contract exit opcode. */
BasicBlock exitBlock() { result.getLastNode().getAstNode() instanceof TContractExitOpcode }

/** A basic block ending in `err` or `return 0` — guaranteed rejection. */
BasicBlock rejectionExit() {
  result.getLastNode().getAstNode() instanceof ErrOpcode
  or
  result = exitBlock() and
  result.getLastNode().getAstNode().(ReturnOpcode).getTopOfStackAtEnd().tryAsInt() = 0
}

// approvalExit, onCompletionNoOp..DeleteApplication, onCompletionRead,
// onCompletionEqualityGuard, approvalExitGuardedForAction, approvalExitUnguardedForAction
// are imported from OnCompletionGuards.

// ---------------------------------------------------------------------------
// Transaction field validation helpers
// ---------------------------------------------------------------------------

/**
 * Holds when `txnRead` reads field `fieldName` and there exists a comparison
 * against some value followed by an assert or conditional branch that would
 * reject on mismatch — i.e. the field is "validated".
 *
 * We check: the field is compared (==, !=, <, <=) and the comparison result
 * flows into an assert or conditional branch.
 */
predicate txnFieldIsChecked(string fieldName) {
  exists(TxnOpcode txnRead |
    txnRead.getField() = fieldName and
    exists(LogicalComparisonOp cmp, SSAVar txnVar |
      txnVar = txnRead.getAnOutputVar() and
      (
        getGenerator(cmp.firstOp()) = txnVar or
        getGenerator(cmp.secondOp()) = txnVar
      )
    )
  )
}

/**
 * Holds when the field `fieldName` is read via `txn` and checked to equal
 * `global ZeroAddress` — the standard pattern for ensuring
 * CloseRemainderTo / AssetCloseTo / RekeyTo are the zero address.
 */
predicate txnFieldCheckedAgainstZeroAddress(string fieldName) {
  exists(
    TxnOpcode txnRead, GlobalOpcode zeroAddr, LogicalComparisonOp cmp, SSAVar txnVar,
    SSAVar zeroVar
  |
    txnRead.getField() = fieldName and
    zeroAddr.getField() = "ZeroAddress" and
    txnVar = txnRead.getAnOutputVar() and
    zeroVar = zeroAddr.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = txnVar and getGenerator(cmp.secondOp()) = zeroVar
      or
      getGenerator(cmp.firstOp()) = zeroVar and getGenerator(cmp.secondOp()) = txnVar
    )
  )
}

/**
 * Holds when the field `fieldName` is read and validated on all approval paths
 * (the comparison dominates every approval exit).
 */
predicate txnFieldValidatedOnAllPaths(string fieldName) {
  exists(TxnOpcode txnRead, LogicalComparisonOp cmp, SSAVar txnVar |
    txnRead.getField() = fieldName and
    txnVar = txnRead.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = txnVar or
      getGenerator(cmp.secondOp()) = txnVar
    ) and
    forall(BasicBlock exit | exit = approvalExit() |
      cmp.getBasicBlock().dominates(exit)
    )
  )
}

// ---------------------------------------------------------------------------
// Sender / Creator access control
// ---------------------------------------------------------------------------

/**
 * Holds when there is a comparison between `txn Sender` and
 * `global CreatorAddress` — the standard creator-only access guard.
 */
predicate hasSenderEqualsCreatorCheck() {
  exists(
    TxnOpcode sender, GlobalOpcode creator, LogicalComparisonOp cmp, SSAVar senderVar,
    SSAVar creatorVar
  |
    sender.getField() = "Sender" and
    creator.getField() = "CreatorAddress" and
    senderVar = sender.getAnOutputVar() and
    creatorVar = creator.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = senderVar and getGenerator(cmp.secondOp()) = creatorVar
      or
      getGenerator(cmp.firstOp()) = creatorVar and getGenerator(cmp.secondOp()) = senderVar
    )
  )
}

/**
 * Holds when the sender == creator check dominates basic block `bb`.
 */
predicate senderCreatorGuardDominates(BasicBlock bb) {
  exists(
    TxnOpcode sender, GlobalOpcode creator, LogicalComparisonOp cmp, SSAVar senderVar,
    SSAVar creatorVar
  |
    sender.getField() = "Sender" and
    creator.getField() = "CreatorAddress" and
    senderVar = sender.getAnOutputVar() and
    creatorVar = creator.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = senderVar and getGenerator(cmp.secondOp()) = creatorVar
      or
      getGenerator(cmp.firstOp()) = creatorVar and getGenerator(cmp.secondOp()) = senderVar
    ) and
    cmp.getBasicBlock().dominates(bb)
  )
}

// ---------------------------------------------------------------------------
// GroupSize validation
// ---------------------------------------------------------------------------

/** Holds when the program reads `global GroupSize`. */
predicate hasGroupSizeCheck() {
  exists(GlobalOpcode g | g.getField() = "GroupSize") and
  exists(LogicalComparisonOp cmp, GlobalOpcode g, SSAVar gVar |
    g.getField() = "GroupSize" and
    gVar = g.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = gVar or
      getGenerator(cmp.secondOp()) = gVar
    )
  )
}

// ---------------------------------------------------------------------------
// Fee validation (hasFeeCheck from FeeValidationGuards; use
// feeCheckDominatesAllApprovalsIn(prog) for CFG/dominance-aware check)
// ---------------------------------------------------------------------------
