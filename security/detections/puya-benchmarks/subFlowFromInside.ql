/**
 * @name Subroutine Flow From Inside Test
 * @description Test if a value sourced inside a subroutine reaches ALL callsites' sinks
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/sub-flow-from-inside
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

from Dataflow::Node src, Dataflow::Node sink
where
  src.getUnderlyingASTNode() instanceof TOpcode_global and
  sink.getUnderlyingASTNode() instanceof TOpcode_app_global_put and
  // Only match nodes in the flow_from_inside_subroutine.teal file range
  src.getUnderlyingASTNode().getLocation().getStartLine() <= 20 and
  sink.getUnderlyingASTNode().getLocation().getStartLine() <= 20 and
  LocalFlow::localFlow(src, sink)
select sink.getUnderlyingASTNode(),
  "global at L" + src.getUnderlyingASTNode().getLocation().getStartLine().toString() +
  " → app_global_put at L" + sink.getUnderlyingASTNode().getLocation().getStartLine().toString()
