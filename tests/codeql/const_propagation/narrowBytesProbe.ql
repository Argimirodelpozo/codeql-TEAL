/**
 * @name Constant propagation — bytes field narrowing probe
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/narrow-bytes
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.BytesPropagation

from AstNode op, string v
where
  (
    op instanceof TxnOpcode or
    op instanceof TxnaOpcode or
    op instanceof GtxnOpcode or
    op instanceof GlobalOpcode
  ) and
  v = tryAsBytes(op.getAnOutputVar())
select op,
  "bytes read " + op.toString() + " at L" + op.getLocation().getStartLine() +
  " narrows to " + v
