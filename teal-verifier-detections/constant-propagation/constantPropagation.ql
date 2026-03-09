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

private import codeql.teal.ast.Transaction


class TConstantOp = TIntegerConstant or TOpcode_bytec or
    TOpcode_bytec_0 or TOpcode_bytec_1 or TOpcode_bytec_2
    or TOpcode_bytec_3 or TOpcode_pushint or TOpcode_pushints
    or TOpcode_pushbytes or TOpcode_pushbytess;


//TODO HERE: full dataflow constant analysis, so we can use
// dataflow for cbmc
//NEED to test this thoroughly, update backend
// frame_dig and frame_bury with their actual
// consumed and produced
// move all consumed/produced logic to the respective opcodes


predicate isConstant(SSAVar var){
    //Either:
    // - this is a constant op, or
    // - there exists data flow from a constant op to here.
    var.getDeclarationNode() instanceof TConstantOp
    or
    exists(Dataflow::Node src, Dataflow::Node sink | 
        src.(Dataflow::SsaDefinitionNode).asDefinition().(SSAWriteDef).getVar().getDeclarationNode() instanceof TConstantOp
        and sink.getUnderlyingASTNode() = var.getDeclarationNode() and
        LocalFlow::localFlow(src, sink)
    )
}


// AstNode lengthExtraction(StackVar var){
//     result instanceof TOpcode_len and 
//     exists(Dataflow::Node src, Dataflow::Node sink | 
//         src.(Dataflow::SsaDefinitionNode).asDefinition().(SSAWriteDef).getVar() = var
//         and sink.getUnderlyingASTNode() = result and
//         LocalFlow::localFlow(src, sink)
//     )
// }

// predicate lengthCheckForVar(StackVar var, AssertOpcode assertion, AstNode comp){
//     comp instanceof TComparison and
//     assertion.getConsumedValues().(SSAWriteDef).getRHS() = comp
//     and
//     comp.getConsumedValues() = var.toDef() and
//     exists(StackVar v | v != var and
//         comp.getConsumedValues() = v.toDef()
//         and exists(v.tryCastToInt()) and 
//         count(comp.getConsumedValues()) = 2
//     )
// }


// from Dataflow::Node op, Dataflow::Node n
// where op.getUnderlyingASTNode().(TxnaOpcode).getField() = "ApplicationArgs" and
// op != n and LocalFlow::localFlow(op, n)
// select op.getUnderlyingASTNode().getLineNumber()*1000 + n.getUnderlyingASTNode().getLineNumber(), op.getUnderlyingASTNode().getFile(), op, n