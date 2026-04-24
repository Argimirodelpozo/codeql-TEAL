/**
 * @name Phi Nodes
 * @description One row per SSA phi (DirectPhi + IndirectPhi). Phis are not
 *              AST nodes and can share (file, line) with the BB's first
 *              opcode, so the row carries (stackIndex, kind) for identity.
 * @id tealql/python-analysis/phi-nodes
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from string kind, int stackIdx, string file, int line
where
  exists(DirectPhi p |
    kind = "DirectPhi" and
    stackIdx = p.getInitialStackIndex() and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine()
  )
  or
  exists(IndirectPhi p |
    kind = "IndirectPhi" and
    stackIdx = p.getInitialStackIndex() and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine()
  )
select file, line, stackIdx, kind
