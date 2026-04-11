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
    txSource.getUnderlyingASTNode() instanceof GtxnOpcode or
    txSource.getUnderlyingASTNode() instanceof GtxnsOpcode or
    txSource.getUnderlyingASTNode() instanceof TxnaOpcode or
    txSource.getUnderlyingASTNode() instanceof TxnOpcode
  ) and
  (
    storageSink.getUnderlyingASTNode() instanceof AppGlobalPutOpcode or
    storageSink.getUnderlyingASTNode() instanceof AppLocalPutOpcode
  ) and
  LocalFlow::localFlow(txSource, storageSink)
select storageSink.getUnderlyingASTNode(), 
  "Storage write receives data from $@", 
  txSource.getUnderlyingASTNode(), 
  "transaction"