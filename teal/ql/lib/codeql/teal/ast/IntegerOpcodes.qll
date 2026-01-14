import codeql.teal.ast.AST
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

class IntegerAddOpcode extends AstNode instanceof TOpcode_add{
    
}

// class LtOpcode extends AstNode instanceof TOpcode_lt{
//     // SSAVar getFirstConsumed(){
        
//     // }

//     boolean tryToPredictResultValue(){
//         result = 
//     }
// }

class IntegerEqualsOpcode extends AstNode instanceof TOpcode_eq{
    int predictValue(){
        exists(int a, int b, StackVar ssa_a, StackVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a = b then result = 1 else result = 0
        )
    }
}

class IntegerNotEqualsOpcode extends AstNode instanceof TOpcode_neq{
    int predictValue(){
        exists(int a, int b, SSAVar ssa_a, SSAVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a != b then result = 1 else result = 0
        )
    }
}

class IntegerLessThanOpcode extends AstNode instanceof TOpcode_lt{
    int predictValue(){
        exists(int a, int b, SSAVar ssa_a, SSAVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a < b then result = 1 else result = 0
        )
    }
}

class IntegerGreaterThanOpcode extends AstNode instanceof TOpcode_gt{
    int predictValue(){
        exists(int a, int b, SSAVar ssa_a, SSAVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a > b then result = 1 else result = 0
        )
    }
}

class IntegerLteOpcode extends AstNode instanceof TOpcode_lte{
    int predictValue(){
        exists(int a, int b, SSAVar ssa_a, SSAVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a <= b then result = 1 else result = 0
        )
    }
}

class IntegerGteOpcode extends AstNode instanceof TOpcode_gte{
    int predictValue(){
        exists(int a, int b, SSAVar ssa_a, SSAVar ssa_b |
            a = ssa_a.tryCastToInt() and
            b = ssa_b.tryCastToInt() and 
            ssa_a != ssa_b |
            if a >= b then result = 1 else result = 0
        )
    }
}