import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter
private import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA
private import codeql.teal.ast.BinaryComparison 


class SimpleConditionalBranches extends AstNode instanceof TSimpleConditionalBranches{
    Label getTargetLabel(){exists(Label l | 
        l.getProgram() = this.getProgram() and (
            l.getName() = toTreeSitter(this).(Teal::BnzOpcode).getChild().(Teal::Token).getValue()
            or l.getName() = toTreeSitter(this).(Teal::BzOpcode).getChild().(Teal::Token).getValue()
        )
        | result = l)}

    StackVar getGoverningVal(){
        result = this.getConsumedVars()
    }

    // predicate govValAmb(){count(this.getGoverningValue()) > 1}
}

class BnzOpcode extends SimpleConditionalBranches instanceof TOpcode_bnz{
    AstNode getNextNode(boolean s){
        s = true and result = this.getTargetLabel() or
        s = false and result = this.getNextLine()
    }
}

class BzOpcode extends SimpleConditionalBranches instanceof TOpcode_bz{
    AstNode getNextNode(boolean s){
        s = false and result = this.getTargetLabel() or
        s = true and result = this.getNextLine()
    }
}

// // multilabel opcodes
// class MatchOpcode extends AstNode instanceof TOpcode_match{

// }