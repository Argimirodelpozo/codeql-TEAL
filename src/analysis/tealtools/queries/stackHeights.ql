/**
 * @name Stack heights per opcode
 * @description One row per AST node × possible stack height before it
 *              executes. Used by the Python stack simulator to bound
 *              the per-BB entry phi-list to actual depth (the SSA
 *              model generates IndirectPhi candidates up to slot 1000,
 *              which the simulation needs to truncate).
 *              Row: file, line, depth.
 * @id tealql/python-analysis/stack-heights
 */

import codeql.teal.ast.AST
import codeql.teal.ast.StackDepth

from AstNode n, int depth
where nodeStackDepth(n, depth)
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       depth
