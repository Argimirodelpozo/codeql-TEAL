/**
 * @name gtxn diag 2
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/gtxn-diag2
 */

import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter

from GtxnOpcode g, string child
where child = toTreeSitter(g).(Teal::GtxnOpcode).getChild().getValue()
select g,
  "line=" + g.getLocation().getStartLine() +
  " child=" + child +
  " field=" + g.getField()
