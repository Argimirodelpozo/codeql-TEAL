import codeql.teal.ast.AST
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

// Mostly constants set by protocol
class GlobalOpcode extends AstNode instanceof TOpcode_global{
    string getField(){
        result = toTreeSitter(this).(Teal::TxnOpcode).getTxnField().(Teal::Token).getValue().toString()
    }

    predicate isIntegerField(){
        this.getField() = "MinTxnFee"
        or this.getField() = "MinBalance"
        or this.getField() = "MaxTxnLife"
        or this.getField() = "LogicSigVersion"
        or this.getField() = "GroupSize"
        or this.getField() = "Round"
    }

    predicate isBytesField(){
        not this.isIntegerField()
    }

    predicate fieldIsProtocolConstant(){
        this.getField() = "MinTxnFee" or
        this.getField() = "MinBalance" or
        this.getField() = "MaxTxnLife" or
        this.getField() = "ZeroAddress" or
        this.getField() = "LogicSigVersion"

        //"GroupSize","Round",
// "LatestTimestamp","CurrentApplicationID","CreatorAddress","CurrentApplicationAddress","GroupID",
// "OpcodeBudget","CallerApplicationID","CallerApplicationAddress","AssetCreateMinBalance",
// "AssetOptInMinBalance","GenesisHash","PayoutsEnabled","PayoutsGoOnlineFee","PayoutsPercent",
// "PayoutsMinBalance","PayoutsMaxBalance"
    }

    // // get a value for constant fields
    // int getValue(){
    // }
}


// ,"MinBalance","MaxTxnLife","ZeroAddress","GroupSize","LogicSigVersion","Round",
// "LatestTimestamp","CurrentApplicationID","CreatorAddress","CurrentApplicationAddress","GroupID",
// "OpcodeBudget","CallerApplicationID","CallerApplicationAddress","AssetCreateMinBalance",
// "AssetOptInMinBalance","GenesisHash","PayoutsEnabled","PayoutsGoOnlineFee","PayoutsPercent",
// "PayoutsMinBalance","PayoutsMaxBalance"