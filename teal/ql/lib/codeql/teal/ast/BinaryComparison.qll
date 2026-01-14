private import codeql.teal.ast.AST
private import codeql.teal.ast.internal.TreeSitter

class TLogicalComparisonOp = TOpcode_lt or TOpcode_lte or TOpcode_gt or TOpcode_gte or 
    TOpcode_eq or TOpcode_neq;

class LogicalComparisonOp extends AstNode instanceof TLogicalComparisonOp{

    Definition firstOp(){result = this.(AstNode).getStackInputByOrder(1)}
    Definition secondOp(){result = this.(AstNode).getStackInputByOrder(2)}
    string getOperator(){result = this.(AstNode).toString()}

    Definition getAnOp(){result = this.firstOp() or result = this.secondOp()}
    // override
    // // string toString(){result = this.firstOp() + " " + this.getOperator() + " " + this.secondOp()}
    // string toString(){result = this.getOperator()}
    // override
    // Location getLocation(){result = this.(AstNode).getLocation()}

    boolean attemptInference(){
        this.getOperator() = ">" and
        if getGenerator(this.firstOp()).tryCastToInt() = getGenerator(this.secondOp()).tryCastToInt()
        then result = true 
        else result = false
    }
}

class EqualsComparisonOpcode extends LogicalComparisonOp{
    EqualsComparisonOpcode(){this.getOperator() = "=="}


}

class NotEqualsComparisonOpcode extends LogicalComparisonOp{
    NotEqualsComparisonOpcode(){this.getOperator() = "!="}
}