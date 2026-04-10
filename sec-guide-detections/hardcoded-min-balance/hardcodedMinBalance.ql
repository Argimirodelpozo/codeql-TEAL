/**
 * @name Hardcoded Minimum Balance
 * @description Detects contracts that subtract a hardcoded constant from the
 *              application balance instead of using the min_balance opcode.
 *              Hardcoded minimum balance assumptions become invalid when the
 *              contract creates boxes, opts into assets, or adds local state.
 *              Contracts may then attempt invalid withdrawals.
 * @kind problem
 * @severity medium
 * @id teal/sec-guide/hardcoded-min-balance
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

/**
 * Holds when a `balance` opcode's result flows into a subtraction
 * where the other operand is a hardcoded integer constant — indicating
 * a hardcoded minimum balance is assumed instead of using `min_balance`.
 */
predicate balanceMinusHardcodedConstant(BalanceOpcode bal, SubOpcode sub) {
  exists(SSAVar balVar, SSAVar constVar |
    balVar = bal.getAnOutputVar() and
    (
      getGenerator(sub.getStackInputByOrder(1)) = balVar or
      getGenerator(sub.getStackInputByOrder(2)) = balVar
    ) and
    (
      constVar = getGenerator(sub.getStackInputByOrder(1)) or
      constVar = getGenerator(sub.getStackInputByOrder(2))
    ) and
    constVar != balVar and
    exists(constVar.tryAsInt())
  )
}

from BalanceOpcode bal, SubOpcode sub
where
  balanceMinusHardcodedConstant(bal, sub) and
  not exists(MinBalanceOpcode minBal | minBal.getProgram() = bal.getProgram())
select sub,
  "Balance minus hardcoded constant — use the min_balance opcode instead to dynamically account for boxes, opt-ins, and local state."
