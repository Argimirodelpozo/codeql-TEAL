/**
 * CFG and dominance-based fee validation for TEAL security analysis.
 *
 * Provides predicates to check whether txn Fee is validated on all approval
 * paths. Uses dominance: a fee check must dominate every approval exit so
 * that no path can approve without going through the fee check.
 *
 * ## How it works
 *
 * - **hasFeeCheck()**: txn Fee is read and compared (<=, <, ==) against a value
 * - **feeCheckDominatesAllApprovalsIn(prog)**: there exists a fee check such
 *   that its block dominates every approval exit in prog — every path to
 *   approval goes through the fee validation
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import codeql.teal.ast.opcodes.Transaction
import codeql.teal.ast.opcodes.Comparison
import codeql.OnCompletionGuards

// ---------------------------------------------------------------------------
// This was taken from TealerCommon (Claude-generated).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Fee validation predicates (CFG/dominance-aware)
// ---------------------------------------------------------------------------

/**
 * Holds when `txn Fee` is read and compared (<=, <, ==) against some value,
 * indicating fee validation.
 */
predicate hasFeeCheck() {
  exists(TxnOpcode fee, LogicalComparisonOp cmp, SSAVar feeVar |
    fee.getField() = "Fee" and
    feeVar = fee.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = feeVar or
      getGenerator(cmp.secondOp()) = feeVar
    )
  )
}

/**
 * Holds when there exists a fee check in program `prog` whose block dominates
 * every approval exit in `prog`. In other words: every path to approval
 * goes through the fee validation — it cannot be bypassed.
 */
predicate feeCheckDominatesAllApprovalsIn(Program prog) {
  exists(TxnOpcode fee, LogicalComparisonOp cmp, SSAVar feeVar |
    fee.getField() = "Fee" and
    feeVar = fee.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = feeVar or
      getGenerator(cmp.secondOp()) = feeVar
    ) and
    cmp.getProgram() = prog and
    forall(BasicBlock exit |
      exit = approvalExit() and
      exit.getFirstNode().getAstNode().getProgram() = prog
    |
      cmp.getBasicBlock().dominates(exit)
    )
  )
}
