/**
 * @name Dummy Data Flow Benchmark
 * @description Track data from group transactions (gtxn) to storage operations.
 * @kind problem
 * @problem.severity recommendation
 * @id teal/benchmark/dummy-flow
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow
import codeql.teal.ast.opcodes.GlobalState

from Dataflow::Node txSource, Dataflow::Node storageSink
where
  (
    // txSource.getUnderlyingASTNode() instanceof TOpcode_dup and
    // txSource.getUnderlyingASTNode().getLocation().getEndLine() = 216

    // txSource.getUnderlyingASTNode() instanceof TOpcode_txna and
    // txSource.getUnderlyingASTNode().(TxnaOpcode).getField() = "ApplicationArgs" and
    // txSource.getUnderlyingASTNode().(TxnaOpcode).getIndex() = 8
  
    txSource.getUnderlyingASTNode() instanceof TOpcode_gtxn or
    txSource.getUnderlyingASTNode() instanceof TOpcode_gtxns or
    txSource.getUnderlyingASTNode() instanceof TOpcode_txna or
    txSource.getUnderlyingASTNode() instanceof TOpcode_txn
  ) 
  and
  (
    storageSink.getUnderlyingASTNode() instanceof TOpcode_app_global_put or
    storageSink.getUnderlyingASTNode() instanceof TOpcode_app_local_put
  ) and
  LocalFlow::localFlow(txSource, storageSink)
select storageSink.getUnderlyingASTNode(), 
  "Storage write receives data from $@", 
  txSource.getUnderlyingASTNode(), 
  "transaction"