import codeql.teal.ast.AST
import codeql.teal.cfg.BasicBlocks


Definition getFinalCondition(SimpleConditionalBranches b){
    result = b.getConsumedValues()
}

