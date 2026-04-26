/**
 * @id tealql/probe-l250
 * @kind table
 */
import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from AstNode n, int ord, Definition def, string kind
where n.getLocation().getStartLine() = 250
  and n.getLocation().getFile().getRelativePath().regexpMatch(".*approval\\.teal")
  and def = n.getStackInputByOrder(ord)
  and (
    def instanceof DirectPhi and kind = "Direct"
    or def instanceof IndirectPhi and kind = "Indirect"
    or def instanceof SSAWriteDef and kind = "Write"
  )
select ord, kind, def.toString()
