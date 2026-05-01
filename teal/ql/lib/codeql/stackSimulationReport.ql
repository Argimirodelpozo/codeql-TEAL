/**
 * @name Stack simulation report
 * @description Per-line IN/OUT stack contents for every executable AST
 *              node in the program, derived from the SSA model. Each row
 *              is `(file, line, col, opcode, in_stack, out_stack)`.
 * @id teal/stack-simulation-report
 */

import codeql.teal.ast.AST
import codeql.teal.ast.StackSimulation

from
  AstNode n, string file, int line, int col, string opcode,
  string inStack, string outStack
where
  not n instanceof Label and
  exists(n.getBasicBlock()) and
  file = n.getLocation().getFile().getRelativePath() and
  line = n.getLocation().getStartLine() and
  col = n.getLocation().getStartColumn() and
  opcode = n.toString() and
  inStack = stackInString(n) and
  outStack = stackOutString(n)
select file, line, col, opcode, inStack, outStack
