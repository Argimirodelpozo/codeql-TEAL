/**
 * Sanity test: TxnOpcode and GtxnOpcode expose their field name
 * via getField(). Catches grammar / extractor regressions that
 * would silently strip the field.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.Transaction

from int line, string opName, string fieldName
where
  exists(TxnOpcode t |
    line = t.getLocation().getStartLine() and
    opName = "txn" and
    fieldName = t.getField()
  )
  or
  exists(GtxnOpcode g |
    line = g.getLocation().getStartLine() and
    opName = "gtxn" and
    fieldName = g.getField()
  )
select line, opName, fieldName order by line
