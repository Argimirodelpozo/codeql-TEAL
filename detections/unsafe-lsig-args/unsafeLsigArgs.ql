/**
 * @name Unsafe LogicSig Argument Usage
 * @description Detects LogicSig contracts that use `arg` opcodes in comparisons
 *              that could serve as access control. LogicSig arguments are NOT
 *              covered by delegation signatures, are visible in plaintext on-chain,
 *              and can be arbitrarily changed per transaction. Using them for
 *              authorization provides zero security.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/unsafe-lsig-args
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

/**
 * An AstNode that is an arg opcode (arg, arg_0, arg_1, arg_2, arg_3).
 */
class AnyArgOpcode extends AstNode {
  AnyArgOpcode() {
    this instanceof ArgOpcode or
    this instanceof Arg0Opcode or
    this instanceof Arg1Opcode or
    this instanceof Arg2Opcode or
    this instanceof Arg3Opcode or
    this instanceof ArgsOpcode
  }
}

/**
 * Holds when an arg value flows into an equality comparison,
 * suggesting it may be used for access control.
 */
predicate argUsedInEqualityCheck(AnyArgOpcode argOp, LogicalComparisonOp cmp) {
  exists(SSAVar argVar |
    argVar = argOp.getAnOutputVar() and
    (
      getGenerator(cmp.firstOp()) = argVar or
      getGenerator(cmp.secondOp()) = argVar
    ) and
    cmp instanceof EqualsComparisonOpcode
  )
}

from AnyArgOpcode argOp, LogicalComparisonOp cmp
where
  argUsedInEqualityCheck(argOp, cmp)
select argOp,
  "LogicSig argument used in equality comparison — args are not covered by delegation signatures and provide zero security for access control."
