/**
 * @name SSA Outputs per Opcode
 * @description For every AstNode that pushes to the stack, one row per
 *              produced SSA var (``output_index`` is 1-based). The var's
 *              declaring line equals ``astLine`` — that plus ``outIdx``
 *              uniquely identifies the ``SSAVar``.
 *
 *              Row: astFile, astLine, outIdx
 * @id tealql/python-analysis/ssa-outputs
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from AstNode n, int outIdx, SSAVar v
where v = n.getOutputVar(outIdx)
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       outIdx
