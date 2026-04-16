/**
 * @name Constant propagation — field narrowing probe
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/narrow
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.ConstantPropagation

from AstNode op, int v
where
  (
    op instanceof TxnOpcode or
    op instanceof TxnaOpcode or
    op instanceof GtxnOpcode or
    op instanceof GlobalOpcode
  ) and
  v = tryAsInt(op.getAnOutputVar())
select op,
  "field read " + op.toString() + " at L" + op.getLocation().getStartLine() +
  " narrows to " + v
