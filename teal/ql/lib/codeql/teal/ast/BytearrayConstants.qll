private import codeql.teal.ast.AST
private import codeql.teal.ast.internal.TreeSitter

class BytecblockOpcode extends AstNode instanceof TOpcode_bytecblock{
    string getValue(int i){
        result = toTreeSitter(this).(Teal::BytecblockOpcode).getChild(i).toString()
    }
}

class BytecOpcode extends AstNode instanceof TOpcode_bytec{
    int getIndex(){
        result = toTreeSitter(this).(Teal::SingleNumericArgumentOpcode).getValue().toString().toInt()
    }

    //TODO: deberia ser el bytecblock MAS CERCANO. Por ahora asumimos que hay uno solo
    string getValue(){
        result = any(BytecblockOpcode bytecblock).getValue(this.getIndex())
    }

    override string toString(){result = this.getValue()}
}

class Bytec0Opcode extends AstNode instanceof TOpcode_bytec_0{
    //TODO: deberia ser el bytecblock MAS CERCANO. Por ahora asumimos que hay uno solo
    string getValue(){
        result = any(BytecblockOpcode bytecblock).getValue(0)
    }

    override string toString(){result = this.getValue()}
}

class Bytec1Opcode extends AstNode instanceof TOpcode_bytec_1{
    //TODO: deberia ser el bytecblock MAS CERCANO. Por ahora asumimos que hay uno solo
    string getValue(){
        result = any(BytecblockOpcode bytecblock).getValue(1)
    }

    override string toString(){result = this.getValue()}
}

class Bytec2Opcode extends AstNode instanceof TOpcode_bytec_2{
    //TODO: deberia ser el bytecblock MAS CERCANO. Por ahora asumimos que hay uno solo
    string getValue(){
        result = any(BytecblockOpcode bytecblock).getValue(2)
    }

    override string toString(){result = this.getValue()}
}

class Bytec3Opcode extends AstNode instanceof TOpcode_bytec_3{
    //TODO: deberia ser el bytecblock MAS CERCANO. Por ahora asumimos que hay uno solo
    string getValue(){
        result = any(BytecblockOpcode bytecblock).getValue(3)
    }

    override string toString(){result = this.getValue()}
}