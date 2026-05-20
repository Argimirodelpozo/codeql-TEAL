/**
 * @name gtxn diagnostic
 * @kind problem
 * @problem.severity recommendation
 * @id teal/probe/gtxn-diag
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from GtxnOpcode g
select g,
  "gtxn at L" + g.getLocation().getStartLine() +
  " toString=" + g.toString()
