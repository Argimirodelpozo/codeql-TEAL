/**
 * @name SSA Inputs per Opcode
 * @description Per AstNode, one row per stack input (ordered by
 *              ``getStackInputByOrder``). The consumed definition may be a
 *              regular SSA write (``SSAWriteDef``), a ``DirectPhi``, or
 *              an ``IndirectPhi``. Downstream consumers identify the
 *              definition via (defFile, defLine, defIdx, defKind):
 *                - SSAWriteDef: defIdx = internalOutputIndex
 *                - DirectPhi / IndirectPhi: defIdx = initialStackIndex
 *
 *              Row: astFile, astLine, ord, defKind, defFile, defLine, defIdx
 * @id tealql/python-analysis/ssa-inputs
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from
  AstNode n, int ord, Definition def,
  string defKind, string defFile, int defLine, int defIdx
where
  def = n.getStackInputByOrder(ord) and
  defFile = def.getLocation().getFile().getRelativePath() and
  defLine = def.getLocation().getStartLine() and
  (
    def instanceof SSAWriteDef and
    defKind = "SSAWriteDef" and
    defIdx = def.(SSAWriteDef).getInternalOutputIndex()
    or
    def instanceof DirectPhi and
    defKind = "DirectPhi" and
    defIdx = def.(DirectPhi).getInitialStackIndex()
    or
    def instanceof IndirectPhi and
    defKind = "IndirectPhi" and
    defIdx = def.(IndirectPhi).getInitialStackIndex()
  )
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       ord,
       defKind, defFile, defLine, defIdx
