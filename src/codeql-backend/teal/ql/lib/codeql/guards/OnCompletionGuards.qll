/**
 * CFG and dominance-based OnCompletion guards for TEAL security analysis.
 *
 * This module provides predicates to check whether approval exits are properly
 * guarded against specific OnCompletion actions (e.g. UpdateApplication=4,
 * DeleteApplication=5) using control-flow and dominance analysis.
 *
 * ## How it works
 *
 * 1. **CFG (Control Flow Graph)**: The TEAL program is represented as basic blocks
 *    connected by edges. A ConditionBlock is a block ending in bnz/bz that
 *    splits control flow. `cb.controls(approvalBB, s)` means: the approval block
 *    is only reachable via the branch with value `s` from the condition block.
 *
 * 2. **Dominance**: Block A dominates block B if every path from entry to B goes
 *    through A. We use this to ensure a guard runs before any approval exit.
 *
 * 3. **SSA (Static Single Assignment)**: We trace values through the stack using
 *    getGenerator() to connect the comparison operands to their sources (txn
 *    OnCompletion vs. integer constant).
 *
 * 4. **Guard logic**: For "reject OnCompletion == 5", we need:
 *    - A comparison (== or !=) of txn OnCompletion to 5
 *    - The branch that leads to approval must be the "non-equality" branch
 *    - So when OnCompletion==5 we take the reject path, not approval
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import codeql.teal.ast.opcodes.Transaction
import codeql.teal.ast.opcodes.Comparison
import codeql.teal.ast.opcodes.ScratchSpace
import codeql.teal.dataflow.ConstantPropagation
private import codeql.teal.cfg.Completion::Completion

// ---------------------------------------------------------------------------
// This came from TealerCommon (Claude-generated/extracted) 
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// OnCompletion constants (AVM spec)
//
// Value  Name              Effect
// -----  ----------------  -------------------------------------------------
// 0      NoOp              Only executes Approval Program, no extra effects
// 1      OptIn             Allocates local state before Approval Program
// 2      CloseOut          Clears local state from sender after Approval
// 3      ClearState        Runs Clear State Program (not Approval), clears state
// 4      UpdateApplication Replaces Approval/Clear State programs after Approval
// 5      DeleteApplication Deletes app parameters from creator after Approval
//
// Use approvalExitUnguardedForAction(approvalBB, onCompletionX()) for any of
// these. Queries stay simple: import OnCompletionGuards and call the predicate.
// ---------------------------------------------------------------------------

int onCompletionNoOp() { result = 0 }
int onCompletionOptIn() { result = 1 }
int onCompletionCloseOut() { result = 2 }
int onCompletionClearState() { result = 3 }
int onCompletionUpdateApplication() { result = 4 }
int onCompletionDeleteApplication() { result = 5 }

/** A `txn OnCompletion` read. */
TxnOpcode onCompletionRead() { result.getField() = "OnCompletion" }

// ---------------------------------------------------------------------------
// Approval exit (block ending in return that may approve)
// ---------------------------------------------------------------------------

/**
 * A basic block ending in `return` where the return value may be non-zero
 * (i.e. the transaction is approved).
 */
BasicBlock approvalExit() {
  result.getLastNode().getAstNode() instanceof ReturnOpcode and
  (
    tryAsInt(result.getLastNode().getAstNode().(ReturnOpcode).getTopOfStackAtEnd()) != 0
    or
    not exists(tryAsInt(result.getLastNode().getAstNode().(ReturnOpcode).getTopOfStackAtEnd()))
  )
}

// ---------------------------------------------------------------------------
// OnCompletion equality guard (CFG-aware)
// ---------------------------------------------------------------------------

/**
 * Holds when SSA variable `v` has a known integer value `val`.
 *
 * Delegates to the top-level `tryAsInt` from `ConstantPropagation.qll`,
 * which already handles literal constants, arithmetic (`+`, `-`, `*`, `/`,
 * `%`), scratch-slot loads, stack manipulation via strict `localFlow`, and
 * (transitively) subroutine passthrough.
 */
private predicate getConstantInt(SSAVar v, int val) {
  val = tryAsInt(v)
}

/**
 * Holds when `cb` is a condition block that compares OnCompletion against
 * constant `actionInt` using `==` or `!=`.
 *
 * - For `==`: equality holds on the true branch (bnz jumps when equal)
 * - For `!=`: equality holds on the false branch (bz jumps when equal)
 *
 * We trace operands via SSA: one side must be txn OnCompletion, the other
 * must be the constant actionInt (literal or computed, e.g. 2+3).
 */
predicate onCompletionEqualityGuard(
  ConditionBlock cb, int actionInt, BooleanSuccessor equalBranch
) {
  exists(
    SimpleConditionalBranches branch, SSAVar gov, AstNode comp, Definition firstDef,
    Definition secondDef, SSAVar firstVar, SSAVar secondVar
  |
    branch.getBasicBlock() = cb and
    gov = branch.getGoverningVal() and
    comp = gov.getDeclarationNode() and
    (
      comp instanceof IntegerEqualsOpcode and equalBranch.getValue() = true
      or
      comp instanceof IntegerNotEqualsOpcode and equalBranch.getValue() = false
    ) and
    firstDef = comp.(LogicalComparisonOp).firstOp() and
    secondDef = comp.(LogicalComparisonOp).secondOp() and
    firstVar = getGenerator(firstDef) and
    secondVar = getGenerator(secondDef) and
    (
      firstVar.getDeclarationNode() = onCompletionRead() and
      getConstantInt(secondVar, actionInt)
      or
      secondVar.getDeclarationNode() = onCompletionRead() and
      getConstantInt(firstVar, actionInt)
    )
  )
}

/**
 * Holds if the approval exit `approvalBB` is guarded for action `actionInt`:
 * an OnCompletion guard exists, and the non-equality branch (where
 * OnCompletion != actionInt) controls the approval exit.
 *
 * So: all paths to approval go through the branch where we determined
 * OnCompletion != actionInt — meaning we reject when OnCompletion == actionInt.
 */
predicate approvalExitGuardedForAction(BasicBlock approvalBB, int actionInt) {
  exists(ConditionBlock cb, BooleanSuccessor equalBranch, BooleanSuccessor nonEqualBranch |
    onCompletionEqualityGuard(cb, actionInt, equalBranch) and
    nonEqualBranch.getValue() != equalBranch.getValue() and
    cb.controls(approvalBB, nonEqualBranch)
  )
}

/**
 * Holds if the approval exit is NOT guarded for action `actionInt`:
 * it can be reached without going through an OnCompletion == actionInt check.
 */
predicate approvalExitUnguardedForAction(BasicBlock approvalBB, int actionInt) {
  approvalBB = approvalExit() and
  actionInt in [0 .. 5] and
  not approvalExitGuardedForAction(approvalBB, actionInt)
}
