private import codeql.teal.ast.AST
private import codeql.teal.ast.internal.TreeSitter


class TIntegerConstant = TOpcode_int or TOpcode_intc or TOpcode_intc_0 or
    TOpcode_intc_1 or TOpcode_intc_2 or TOpcode_intc_3 or TOpcode_pushint;


class IntegerConstant extends AstNode instanceof TIntegerConstant{
    abstract int getValue();
}


class IntcblockOpcode extends AstNode instanceof TOpcode_intcblock{
    int getValue(int i){
        result = toTreeSitter(this).(Teal::IntcblockOpcode).getValue(i).toString().toInt()
    }
}


class IntcOpcode extends IntegerConstant instanceof TOpcode_intc{
    int getIndex(){
        result = toTreeSitter(this).(Teal::IntcOpcode).getValue().toString().toInt()
    }

    //TODO: deberia ser el intcblock MAS CERCANO. Por ahora asumimos que hay uno solo
    override int getValue(){
        exists(IntcblockOpcode op |
            op.getBasicBlock().dominates(this.getBasicBlock()) and
            result = op.getValue(this.getIndex())
        )
    }

    override string toString(){result = this.getValue().toString()}
}

class Intc0Opcode extends IntegerConstant instanceof TOpcode_intc_0{
    //TODO: deberia ser el intcblock MAS CERCANO. Por ahora asumimos que hay uno solo
    override int getValue(){
        exists(IntcblockOpcode op |
            op.getBasicBlock().dominates(this.getBasicBlock()) and
            result = op.getValue(0)
        )
    }

    override string toString(){result = this.getValue().toString()}
}

class Intc1Opcode extends IntegerConstant instanceof TOpcode_intc_1{

    //TODO: deberia ser el intcblock MAS CERCANO. Por ahora asumimos que hay uno solo
    override int getValue(){
        exists(IntcblockOpcode op |
            op.getBasicBlock().dominates(this.getBasicBlock()) and
            result = op.getValue(1)
        )
    }

    override string toString(){result = this.getValue().toString()}
}

class Intc2Opcode extends IntegerConstant instanceof TOpcode_intc_2{

    //TODO: deberia ser el intcblock MAS CERCANO. Por ahora asumimos que hay uno solo
    override int getValue(){
        exists(IntcblockOpcode op |
            op.getBasicBlock().dominates(this.getBasicBlock()) and
            result = op.getValue(2)
        )
    }

    override string toString(){result = this.getValue().toString()}
}

class Intc3Opcode extends IntegerConstant instanceof TOpcode_intc_3{

    //TODO: deberia ser el intcblock MAS CERCANO. Por ahora asumimos que hay uno solo
    override int getValue(){
        exists(IntcblockOpcode op |
            op.getBasicBlock().dominates(this.getBasicBlock()) and
            result = op.getValue(3)
        )
    }

    override string toString(){result = this.getValue().toString()}
}

class PushintOpocode extends IntegerConstant instanceof TOpcode_pushint{
    override int getValue(){
        result = toTreeSitter(this).(Teal::SingleNumericArgumentOpcode).getValue().toString().toInt()
    }

    override string toString(){result = this.getValue().toString()}
}