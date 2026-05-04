/**
 * Verify SwitchOpcode resolves all its target labels in source order.
 * The same `MultiTargetConditionalBranch` API is shared with
 * MatchOpcode, so this also exercises the underlying tree-sitter
 * child-extraction predicate.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.ControlFlow

from SwitchOpcode s, int i, string label
where label = s.getTargetLabel(i).getName()
select s.getLocation().getStartLine() as line, i, label order by line, i
