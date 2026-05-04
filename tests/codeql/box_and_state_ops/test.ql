/**
 * AST class recognition for box-storage and global-state opcodes.
 * If a grammar rename or extractor change drops one of these
 * `TOpcode_*` types, the corresponding row disappears — making
 * the regression visible without waiting for downstream detector
 * misbehaviour.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.BoxStorage
import codeql.teal.ast.opcodes.GlobalState

from int line, string opName
where
  exists(BoxPutOpcode b | line = b.getLocation().getStartLine() and opName = "box_put")
  or
  exists(BoxGetOpcode b | line = b.getLocation().getStartLine() and opName = "box_get")
  or
  exists(AppGlobalPutOpcode a | line = a.getLocation().getStartLine() and opName = "app_global_put")
  or
  exists(AppGlobalGetOpcode a | line = a.getLocation().getStartLine() and opName = "app_global_get")
select line, opName order by line
