/**
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/dig6-iter
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

// Count how many rows "from SSAVar v" produces for the dig.
from SSAVar v, int idx
where
  v.getLineNumberInFile() = 11 and
  idx = v.getInternalOutputIndex()
select idx, "got a row with idx=" + idx.toString()
