/**
 * @name Inner transaction fields
 * @description One row per ``(start, end, itxn_field)`` triple where
 *              ``contributesToItxn`` holds. ``start`` is an
 *              ``itxn_begin`` or ``itxn_next``; ``end`` is the next
 *              ``itxn_next`` or ``itxn_submit`` along the CFG. The
 *              consumed operand is reported by ``(kind, file, line,
 *              idx)`` so the python side can resolve it via
 *              ``SSAProgram.var`` / ``.phi``.
 *
 *              Row: fieldFile, fieldLine, fieldName, startLine,
 *                   startKind, endLine, endKind, defKind, defFile,
 *                   defLine, defIdx
 * @id tealql/python-analysis/inner-txn-fields
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.ast.InnerTransactions

string startKind(InnerTransactionStart s) {
  s instanceof InnerTransactionBegin and result = "itxn_begin"
  or
  s instanceof InnerTransactionNext and result = "itxn_next"
}

string endKind(InnerTransactionEnd e) {
  e instanceof InnerTransactionSubmit and result = "itxn_submit"
  or
  e instanceof InnerTransactionNext and result = "itxn_next"
}

/**
 * Tightened version of ``InnerTransactionField.contributesToItxn``.
 * Keeps only the *closest* enclosing (start, end) pair per field:
 *   - no other ``InnerTransactionStart`` between ``start`` and ``field``,
 *   - no other ``InnerTransactionEnd`` between ``field`` and ``end``.
 * Without this, a field in the first txn of a grouped submit
 * (``begin → field → next → submit``) would also pair with the outer
 * ``(begin, submit)`` because ``contributesToItxn`` only checks reach,
 * not minimality.
 */
predicate immediateContributes(
  InnerTransactionField f, InnerTransactionStart s, InnerTransactionEnd e
) {
  s != e and s.reaches(f) and f.reaches(e) and
  not exists(InnerTransactionStart s2 |
    s2 != s and s.reaches(s2) and s2.reaches(f)
  ) and
  not exists(InnerTransactionEnd e2 |
    e2 != e and f.reaches(e2) and e2.reaches(e)
  )
}

from
  InnerTransactionField field, InnerTransactionStart start, InnerTransactionEnd end,
  Definition def, string defKind, string defFile, int defLine, int defIdx
where
  immediateContributes(field, start, end) and
  def = field.getConsumedValues() and
  defFile = def.getLocation().getFile().getRelativePath() and
  defLine = def.getLocation().getStartLine() and
  (
    def instanceof SSAWriteDef and defKind = "SSAVar" and
    defIdx = def.(SSAWriteDef).getInternalOutputIndex()
    or
    def instanceof DirectPhi and defKind = "DirectPhi" and
    defIdx = def.(DirectPhi).getInitialStackIndex()
    or
    def instanceof IndirectPhi and defKind = "IndirectPhi" and
    defIdx = def.(IndirectPhi).getInitialStackIndex()
  )
select
  field.getLocation().getFile().getRelativePath() as fieldFile,
  field.getLocation().getStartLine() as fieldLine,
  field.getItxnField() as fieldName,
  start.getLocation().getStartLine() as startLine,
  startKind(start) as startKind,
  end.getLocation().getStartLine() as endLine,
  endKind(end) as endKind,
  defKind, defFile, defLine, defIdx
