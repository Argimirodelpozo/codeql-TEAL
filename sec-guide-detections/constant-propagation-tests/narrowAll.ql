/**
 * @name Narrowing — combined int + bytes probe
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/narrow-all
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.ConstantPropagation
import codeql.teal.dataflow.BytesPropagation

predicate isFieldRead(AstNode op) {
  op instanceof TxnOpcode or
  op instanceof TxnaOpcode or
  op instanceof GtxnOpcode or
  op instanceof GlobalOpcode
}

string lineOf(AstNode op) { result = op.getLocation().getStartLine().toString() }

from AstNode op, string kind, string value
where
  isFieldRead(op) and
  (
    value = tryAsInt(op.getAnOutputVar()).toString() and kind = "int"
    or
    value = tryAsBytes(op.getAnOutputVar()) and kind = "bytes"
  )
select op,
  "L" + lineOf(op) + " " + op.toString() + " narrows[" + kind + "] to " + value
