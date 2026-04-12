/**
 * @name Nested Subroutine Flow Test
 * @description Four scenarios with nested subroutines
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/nested-flow
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

predicate isTestSource(Dataflow::Node n) {
  (
    // txna args (top-level sources used by Test A and Test B)
    n.getUnderlyingASTNode() instanceof TOpcode_txna
    or
    // global (internal source inside outer_with_inner_global, Test C)
    n.getUnderlyingASTNode() instanceof TOpcode_global
    or
    // txn (internal source inside nested_internal_source, Test D)
    n.getUnderlyingASTNode() instanceof TOpcode_txn
  )
}

predicate isTestSink(Dataflow::Node n) {
  n.getUnderlyingASTNode() instanceof TOpcode_app_global_put
}

from Dataflow::Node src, Dataflow::Node sink
where
  isTestSource(src) and isTestSink(sink) and
  LocalFlow::localFlow(src, sink)
select sink.getUnderlyingASTNode(),
  src.getUnderlyingASTNode().toString() +
  " at L" + src.getUnderlyingASTNode().getLocation().getStartLine().toString() +
  " → app_global_put at L" + sink.getUnderlyingASTNode().getLocation().getStartLine().toString()
