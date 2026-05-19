/**
 * Shared predicates for security-guide detections.
 *
 * Provides reusable building blocks for checking:
 * - Approval/rejection exit paths
 * - Transaction field validation (CloseRemainderTo, AssetCloseTo, RekeyTo, Fee)
 * - Sender/Creator access control guards
 * - OnCompletion action checks
 * - GroupSize validation
 * - Inner transaction field inspection
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import codeql.teal.dataflow.Dataflow
import codeql.guards.OnCompletionGuards
import codeql.guards.FeeValidationGuards
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
  tryAsInt(result.getLastNode().getAstNode().(ReturnOpcode).getTopOfStackAtEnd()) = 0
}

// approvalExit, onCompletionNoOp..DeleteApplication, onCompletionRead,
// onCompletionEqualityGuard, approvalExitGuardedForAction, approvalExitUnguardedForAction
// are imported from OnCompletionGuards.

// hasFeeCheck, feeCheckDominatesAllApprovalsIn are imported from FeeValidationGuards.

// ---------------------------------------------------------------------------
// Transaction field validation helpers
// ---------------------------------------------------------------------------

/**
 * Holds when `txnRead` reads field `fieldName` and there exists a comparison
 * against some value — i.e. the field is "validated".
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
 * `global ZeroAddress`.
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

/**
 * Holds when a `txn fieldName` read flows into the comparison `cmp`.
 *
 * Two cases are unioned:
 *
 * 1. `LocalFlow::localFlow` connects the txn read to the cmp directly.
 *    This already handles checks that live in a called sub of signature
 *    `proto 0 0` (via `callsubBridge`), checks routed through scratch
 *    slots (via `scratchBridge`), and branch-local cmps.
 *
 * 2. The caller pushes `txn fieldName` as an explicit proto-sub argument
 *    and the sub's body consumes that arg in a cmp. `LocalFlow` alone
 *    can't express this because the subroutine entry phi is a barrier at
 *    the top level (to prevent cross-callsite contamination through
 *    retsub). Instead we pattern-match the callsite: find the caller's
 *    `argVar` at input position `inIdx`, the matching sub entry phi at
 *    the same `inIdx`, and use `SubroutineFlow::flowThroughSubroutine`
 *    (which does NOT apply the entry-phi barrier) to check the cmp is
 *    reachable from the entry phi inside the sub body. This is exactly
 *    the "flow INTO the sub" direction that `callsubBridge` doesn't
 *    cover — `callsubBridge` only handles the "arg goes in and comes back
 *    out via retsub" direction.
 */
predicate txnFieldFlowsToComparison(string fieldName, LogicalComparisonOp cmp) {
  exists(TxnOpcode txnRead, Dataflow::Node src, Dataflow::Node sink |
    txnRead.getField() = fieldName and
    src.getUnderlyingASTNode() = txnRead and
    sink.getUnderlyingASTNode() = cmp and
    LocalFlow::localFlow(src, sink)
  )
  or
  exists(
    TxnOpcode txnRead, CallsubOpcode cs, Subroutine sub, int inIdx,
    SSAVar argVar, DirectPhi entryPhi, Dataflow::Node entryNode, Dataflow::Node cmpNode
  |
    txnRead.getField() = fieldName and
    // Caller's arg at the callsite: it was declared by `txn fieldName`
    // and is sitting at stack position `inIdx` when the callsub fires.
    argVar.getBasicBlock() = cs.getBasicBlock() and
    argVar.outStackOrder() = inIdx and
    argVar.getDeclarationNode() = txnRead and
    sub = cs.getSubroutine() and
    // Sub's entry phi for that same stack position.
    entryPhi.getBasicBlock() = sub.getBasicBlock() and
    entryPhi.getInitialStackIndex() = inIdx and
    entryNode.(Dataflow::SsaDefinitionNode).asDefinition() = entryPhi and
    // The cmp must lie inside the sub body and be reachable from the entry
    // phi via SubroutineFlow (no entry-phi barrier inside the sub).
    cmpNode.getUnderlyingASTNode() = cmp and
    SubroutineFlow::flowThroughSubroutine(entryNode, cmpNode)
  )
}

/**
 * The set of `txn` field names for which the dataflow-aware protection
 * analysis is defined. Used to positively bind `fieldName` before it appears
 * inside `not`-clauses in `reachableWithoutProtection` /
 * `approvalExitProtectedForField`. Add a field name here to make the
 * exit-protection predicates queryable for it.
 */
string protectableField() {
  result = ["RekeyTo", "CloseRemainderTo", "AssetCloseTo", "Fee"]
}

/**
 * Holds when `def`'s output has a forward SSA use chain that terminates
 * in some opcode that enforces rejection when the original value is false:
 *
 *  - `assert` — fails on 0.
 *  - `bnz target` whose fall-through is `err` — on 0 the fall-through
 *    runs, so `err` fires.
 *  - `bz target` whose target is `err` — on 0 the branch is taken to
 *    `err`.
 *
 * Unlike `LocalFlow::localFlow`, this walks through ALL consuming opcodes
 * — including `&&`, `||`, `dup`, and any other boolean/stack compositors
 * that are excluded from `LocalFlow`'s pass-through list — so patterns
 * like `cmp1; cmp2; &&; assert` and `cmp; dup; bnz target; err` are
 * recognized as enforcement.
 *
 * An exhausted chain (def consumed by a NoOutputNode that isn't one of
 * the recognized enforcement sinks, e.g. `pop` or `bz approve`) does not
 * reach enforcement.
 */
predicate defForwardReachesAssert(Definition def) {
  // Base: def is consumed directly by an assert.
  exists(AssertOpcode a | a.getConsumedValues() = def)
  or
  // Base: def is consumed by `bnz target` whose fall-through is `err`.
  // On cmp=false the bnz is not taken, fall-through runs, err rejects.
  exists(BnzOpcode bnz |
    bnz.getConsumedValues() = def and
    bnz.getNextLine() instanceof ErrOpcode
  )
  or
  // Base: def is consumed by `bz target` whose target's first op is `err`.
  // On cmp=false the branch is taken to `target`, which immediately errs.
  exists(BzOpcode bz |
    bz.getConsumedValues() = def and
    bz.getTargetLabel().getNextLine() instanceof ErrOpcode
  )
  or
  // Step: def is consumed by some SSA-def-producing opcode whose own def
  // reaches enforcement.
  exists(SSAWriteDef next |
    next.getRHS().getConsumedValues() = def and
    defForwardReachesAssert(next)
  )
}

/**
 * Holds when `cmp`'s boolean output is effectively enforced — i.e. when
 * `cmp` evaluates false the program is guaranteed to reject. Accepted
 * patterns are enumerated in `defForwardReachesAssert`.
 *
 * Known limitation: composing via `||` (e.g. `rekeyOk || senderEqReceiver;
 * assert`) still counts as enforcement here, even though an attacker who
 * controls RekeyTo can slip through when the other operand is true.
 * Detecting that pattern requires reasoning about the semantic enforcement
 * of the cmp, not just reachability of an assert — out of scope for v1.
 */
predicate cmpReachesAssert(LogicalComparisonOp cmp) {
  exists(SSAWriteDef cmpDef |
    cmpDef.getRHS() = cmp and
    defForwardReachesAssert(cmpDef)
  )
}

/**
 * Holds when basic block `bb` contains a comparison that receives dataflow
 * from `txn fieldName` AND whose result is consumed by an `assert` — so
 * the check actually forces rejection when the field is not equal to the
 * expected value.
 */
predicate isProtectedBB(BasicBlock bb, string fieldName) {
  fieldName = protectableField() and
  exists(LogicalComparisonOp cmp |
    txnFieldFlowsToComparison(fieldName, cmp) and
    cmpReachesAssert(cmp) and
    cmp.getBasicBlock() = bb
  )
}

/**
 * Holds when there is a CFG path from some program-entry BB (a BB with no
 * predecessors) to `bb` that does not traverse any `isProtectedBB(_, fieldName)`
 * basic block — including `bb` itself.
 *
 * Read negatively: `reachableWithoutProtection(exit, F)` means "there is a
 * concrete path from entry to `exit` on which NO `txn F` check ever runs".
 * An approval exit satisfying this is reported as unprotected.
 *
 * This is strictly stronger than the old dominance-based check: it correctly
 * handles "check replicated per branch" (every branch performs its own check,
 * so even though no single cmp BB dominates the merged exit, every path to
 * the exit crosses *some* protective BB — so this predicate fails on the
 * exit and no alert fires). It also handles sub-guarded, proto-sub-guarded,
 * and scratch-guarded checks via the flow-based `isProtectedBB`.
 */
predicate reachableWithoutProtection(BasicBlock bb, string fieldName) {
  fieldName = protectableField() and
  not isProtectedBB(bb, fieldName) and
  (
    not exists(bb.getAPredecessor())
    or
    exists(BasicBlock pred |
      pred = bb.getAPredecessor() and
      reachableWithoutProtection(pred, fieldName)
    )
  )
}

/**
 * Holds when approval exit BB `exit` is protected for field `fieldName`:
 * every path from any program entry to `exit` crosses at least one BB that
 * runs a comparison receiving flow from `txn fieldName`.
 */
predicate approvalExitProtectedForField(BasicBlock exit, string fieldName) {
  fieldName = protectableField() and
  exit = approvalExit() and
  not reachableWithoutProtection(exit, fieldName)
}


// ---------------------------------------------------------------------------
// Sender / Creator access control
// ---------------------------------------------------------------------------

/**
 * Holds when there is a comparison between `txn Sender` and
 * `global CreatorAddress`.
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

/** Holds when the program reads and validates `global GroupSize`. */
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
// Inner transaction helpers
// ---------------------------------------------------------------------------

/**
 * Holds when an inner transaction field is set to a specific field name.
 */
predicate innerTxnSetsField(InnerTransactionField itxnField, string fieldName) {
  itxnField.getItxnField() = fieldName
}

/**
 * Holds when an inner transaction sets a fee to a non-zero value.
 */
predicate innerTxnSetsNonZeroFee(InnerTransactionField itxnField) {
  itxnField.getItxnField() = "Fee" and
  exists(SSAVar feeVal |
    feeVal = itxnField.getItxnFieldVal() and
    tryAsInt(feeVal) != 0
  )
}
