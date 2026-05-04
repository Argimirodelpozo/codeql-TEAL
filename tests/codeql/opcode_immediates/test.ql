/**
 * Verify TxnaOpcode / GtxnOpcode return their parameterised
 * immediates: txna's array index, gtxn's group index + field name.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.Transaction

from int line, string opName, string detail
where
  exists(TxnaOpcode t |
    line = t.getLocation().getStartLine() and
    opName = "txna" and
    detail = "ApplicationArgs[" + t.getIndex().toString() + "]"
  )
  or
  exists(GtxnOpcode g |
    line = g.getLocation().getStartLine() and
    opName = "gtxn" and
    detail = "[" + g.getIndex().toString() + "]." + g.getField()
  )
select line, opName, detail order by line
