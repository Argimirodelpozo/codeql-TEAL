/**
 * @kind problem
 * @id teal/proto-check
 */
import codeql.teal.ast.AST

from CallsubOpcode cs
where not exists(cs.getSubroutine().getAffectingProto())
select cs, "callsub without proto"
