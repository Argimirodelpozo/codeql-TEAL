import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

class TxnOpcode extends AstNode instanceof TOpcode_txn{

}

class TxnaOpcode extends AstNode instanceof TOpcode_txna{
    string getField(){
        result = toTreeSitter(this).(Teal::TxnaOpcode).getTxnaField()
    }

    int getIndex(){
        result = toTreeSitter(this).(Teal::TxnaOpcode).getIndex().getValue().toInt()
    }
}

AstNode getAppArgsRead(int i){result.(TxnaOpcode).getField() = "ApplicationArgs" and
    result.(TxnaOpcode).getIndex() = i}