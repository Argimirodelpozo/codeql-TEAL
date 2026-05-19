/**
 * @name Scratch Flow Test
 * @description Test that flow propagates through store/load scratch slots
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/scratch-flow
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

from Dataflow::Node src, Dataflow::Node sink
where
  src.getUnderlyingASTNode() instanceof TOpcode_txna and
  sink.getUnderlyingASTNode() instanceof TOpcode_app_global_put and
  LocalFlow::localFlow(src, sink)
select sink.getUnderlyingASTNode(),
  "txna at L" + src.getUnderlyingASTNode().getLocation().getStartLine().toString() +
  " → app_global_put at L" + sink.getUnderlyingASTNode().getLocation().getStartLine().toString()
