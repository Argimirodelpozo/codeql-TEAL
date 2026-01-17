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
        if getGenerator(this.firstOp()).tryAsInt() = getGenerator(this.secondOp()).tryAsInt()
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


//TODO: a function that says:
// given this binary op comparison, and given this op in the code, does it hold
//  that being in this specific place mean the binary op is implied to be true/false?
//  this means we have to follow the binop into AND conditions, jumps, and through asserts,
//  and then asess dominance of the block where it stops having controlflow influence

//auxiliary predicate:
// given a binary op, what is the extent of its influence in CFG?
// logical/boolean dataflow and find all sinks
// in this dataflow scenario, AND is let through
// or creates uncertainty (it may or may not be through)
// not cuts, and so does any consumption