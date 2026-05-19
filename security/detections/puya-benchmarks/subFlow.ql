/**
 * @name Subroutine Flow Test
 * @description Test if txna flows through a subroutine to app_global_put
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/sub-flow
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

from Dataflow::Node txSource, Dataflow::Node storageSink
where
  txSource.getUnderlyingASTNode() instanceof TOpcode_txna and
  txSource.getUnderlyingASTNode().getLocation().getStartLine() <= 20 and
  storageSink.getUnderlyingASTNode() instanceof TOpcode_app_global_put and
  LocalFlow::localFlow(txSource, storageSink)
select storageSink.getUnderlyingASTNode(),
  "txna at L" + txSource.getUnderlyingASTNode().getLocation().getStartLine().toString() +
  " → app_global_put at L" + storageSink.getUnderlyingASTNode().getLocation().getStartLine().toString()
