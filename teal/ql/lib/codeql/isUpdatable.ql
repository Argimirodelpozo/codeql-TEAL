// To create db, from root folder do:
// codeql database create --overwrite --search-path codeql/teal/extractor-pack -l teal test-projects/db1 -s test-projects/

private import codeql.teal.ast.internal.TreeSitter
private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.cfg.CFG::CfgImpl
private import codeql.teal.cfg.CFG
private import codeql.teal.ast.InnerTransactions
private import codeql.teal.dataflow.Dataflow
private import codeql.teal.ast.BinaryComparison

private import codeql.teal.ast.Transaction

// I want to know if there exists a path flowing into a return 1, that does not imply
// txn.onComplete != UPDATE.
// This might be implied by:
// onComplete == UPDATE =>(True)
// onComplete != UPDATE =>(False)
// onComplete == anything other than UPDATE (True)
// assert onComplete == UPDATE
// assert onComplete == anything other than Update




from Dataflow::Node op, Dataflow::Node n
where op.getUnderlyingASTNode().(TxnaOpcode).getField() = "ApplicationArgs" and
op != n and LocalFlow::localFlow(op, n)
select op.getUnderlyingASTNode().getLineNumber()*1000 + n.getUnderlyingASTNode().getLineNumber(), op.getUnderlyingASTNode().getFile(), op, n