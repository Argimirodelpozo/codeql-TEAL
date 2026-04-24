/**
 * @name Resolved Constant Values per Opcode
 * @description For every ``intc_*``, ``intc``, ``bytec_*``, ``bytec`` opcode
 *              (and any other ``IntegerConstant`` / ``BytesConstant`` that
 *              carries a resolved compile-time value), emit one row with
 *              the value as seen through ``intcblock`` / ``bytecblock``.
 *
 *              Row: astFile, astLine, kind, value
 *              where kind ∈ {"int", "bytes"}.
 * @id tealql/python-analysis/const-values
 */

import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.Constants

from AstNode n, string kind, string value
where
  exists(IntegerConstant ic |
    ic = n and kind = "int" and value = ic.getValue().toString()
  )
  or
  exists(BytesConstant bc |
    bc = n and kind = "bytes" and value = bc.getValue()
  )
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       kind, value
