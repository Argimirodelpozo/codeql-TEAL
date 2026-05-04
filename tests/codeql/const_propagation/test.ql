/**
 * Constant propagation through identity-preserving ops + arithmetic
 * via ``codeql.teal.dataflow.ConstantPropagation``.
 *
 * Each row is an SSAVar that the lib provably narrows to a single
 * integer literal: ``(line, outIdx, value)``. Loss of any of these
 * rows would mean the lib stopped tracking constants through the
 * relevant op family — silently breaks ``mustValues.ql``,
 * ``InnerTxnReport`` value resolution, and any detector that treats
 * a const as a known literal.
 */
import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.ConstantPropagation

from int line, int outIdx, int value, AstNode declNode, SSAVar v
where
  v = MkSSAVar(outIdx, declNode) and
  line = declNode.getLocation().getStartLine() and
  value = tryAsInt(v) and
  strictcount(int m | m = tryAsInt(v)) = 1
select line, outIdx, value order by line, outIdx
