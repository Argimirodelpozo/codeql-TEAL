/**
 * @name bytes diag
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/bytes-diag
 */

import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter

from PushbytesOpcode p
select p,
  "L" + p.getLocation().getStartLine() +
  " childStr=" + toTreeSitter(p).(Teal::PushbytesOpcode).getValue().toString() +
  " childClass=" + toTreeSitter(p).(Teal::PushbytesOpcode).getValue().getAPrimaryQlClass()
