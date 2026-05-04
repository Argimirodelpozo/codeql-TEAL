/**
 * Verifies the constant-pusher classes (`IntegerConstant`,
 * `BytesConstant`) expose their literal values via `getValue()`.
 * Forms the input substrate for `mustValues.ql` / SSA const
 * propagation; if `getValue()` regresses, downstream taint and
 * detector behaviour silently changes.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.Constants

from int line, string kind, string value
where
  exists(IntegerConstant ic |
    line = ic.getLocation().getStartLine() and
    kind = "int" and
    value = ic.getValue().toString()
  )
  or
  exists(BytesConstant bc |
    line = bc.getLocation().getStartLine() and
    kind = "bytes" and
    value = bc.getValue()
  )
select line, kind, value order by line
