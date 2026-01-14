import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

class TxnOpcode extends AstNode instanceof TOpcode_txn{
    string getField(){
        result = toTreeSitter(this).(Teal::TxnOpcode).getTxnField().(Teal::Token).getValue().toString()
    }

    // Todo: finish all fields in all txn ops. Then see if hte bug is fixed

    predicate isIntegerField(){
        this.getField() = "NumApprovalProgramPages" or
        this.getField() = "NumClearProgramPages" or
        this.getField() = "Nonparticipation" or
        this.getField() = "ExtraProgramPages" or
        this.getField() = "NumAppArgs" or
        this.getField() = "OnCompletion" or
        this.getField() = "TypeEnum"
    }

    predicate isBytesField(){
        not this.isIntegerField()
    }

    //TODO: review limits
    int bounded(){
        this.getField() = "NumApprovalProgramPages" and result in [0 .. 4] or
        this.getField() = "NumClearProgramPages" and result in [0 .. 4] or
        this.getField() = "Nonparticipation" and result in [0 .. 1] or
        this.getField() = "ExtraProgramPages" and result in [0 .. 4] or
        this.getField() = "NumAppArgs" and result in 
            [0 .. max(getAppArgsRead(_, this.getProgram()).(TxnaOpcode).getIndex())] or
        this.getField() = "OnCompletion" and result in [0 .. 5] or
        this.getField() = "Type" and result in [0 .. 8]


        // this = "Sender" or this = "Fee" or this = "FirstValid" or 
        // this = "FirstValidTime" or this = "LastValid" or this = "Note" or 
        // this = "Lease" or this = "Receiver" or this = "Amount" or this = "CloseRemainderTo" or 
        // this = "VotePK" or this = "SelectionPK" or this = "VoteFirst" or this = "VoteLast" or 
        // this = "VoteKeyDilution" or this = "Type" or this = "TypeEnum" or this = "XferAsset" or 
        // this = "AssetAmount" or this = "AssetSender" or this = "AssetReceiver" or 
        // this = "AssetCloseTo" or this = "GroupIndex" or this = "TxID" or this = "ApplicationID" or 
        // this = "NumAccounts" or 
        // this = "ApprovalProgram" or this = "ClearStateProgram" or this = "RekeyTo" or 
        // this = "ConfigAsset" or this = "ConfigAssetTotal" or this = "ConfigAssetDecimals" or 
        // this = "ConfigAssetDefaultFrozen" or this = "ConfigAssetUnitName" or 
        // this = "ConfigAssetName" or this = "ConfigAssetURL" or this = "ConfigAssetMetadataHash" or 
        // this = "ConfigAssetManager" or this = "ConfigAssetReserve" or this = "ConfigAssetFreeze" or 
        // this = "ConfigAssetClawback" or this = "FreezeAsset" or this = "FreezeAssetAccount" or 
        // this = "FreezeAssetFrozen" or this = "NumAssets" or this = "NumApplications" or 
        // this = "GlobalNumUint" or this = "GlobalNumByteSlice" or this = "LocalNumUint" or 
        // this = "LocalNumByteSlice" or 
        // this = "NumLogs" or this = "CreatedAssetID" or this = "CreatedApplicationID" or 
        // this = "LastLog" or this = "StateProofPK"
    }
}

class TxnaOpcode extends AstNode instanceof TOpcode_txna{
    string getField(){
        result = toTreeSitter(this).(Teal::TxnaOpcode).getTxnArrayField()
    }

    int getIndex(){
        result = toTreeSitter(this).(Teal::TxnaOpcode).getIndex().getValue().toInt()
    }

    predicate isIntegerField(){
        this.getField() = "Assets" or
        this.getField() = "Applications"
    }

    predicate isBytesField(){
        not this.isIntegerField()
    }

    predicate isAddressField(){
        this.isBytesField() and
        this.getField() = "Accounts"
    }
}

AstNode getAppArgsRead(int i, Program p){result.(TxnaOpcode).getField() = "ApplicationArgs" and
    result.(TxnaOpcode).getIndex() = i and result.getProgram() = p}


AstNode getOnCompletionUsage(){result.(TxnaOpcode).getField() = "OnCompletion"}

class GtxnOpcode extends AstNode instanceof TOpcode_gtxn{
    string getField(){
        result = toTreeSitter(this).(Teal::GtxnOpcode).getTxnField().(Teal::Token).getValue().toString()
    }

    predicate isIntegerField(){
        this.getField() = "NumApprovalProgramPages" or
        this.getField() = "NumClearProgramPages" or
        this.getField() = "Nonparticipation" or
        this.getField() = "ExtraProgramPages" or
        this.getField() = "NumAppArgs" or
        this.getField() = "OnCompletion" or
        this.getField() = "Type"
    }

    predicate isBytesField(){
        not this.isIntegerField()
    }
}

class GtxnsOpcode extends AstNode instanceof TOpcode_gtxns{
       string getField(){
        result = toTreeSitter(this).(Teal::GtxnsOpcode).getTxnField().(Teal::Token).getValue().toString()
    }

    predicate isIntegerField(){
        this.getField() = "NumApprovalProgramPages" or
        this.getField() = "NumClearProgramPages" or
        this.getField() = "Nonparticipation" or
        this.getField() = "ExtraProgramPages" or
        this.getField() = "NumAppArgs" or
        this.getField() = "OnCompletion" or
        this.getField() = "Type"
    }

    predicate isBytesField(){
        not this.isIntegerField()
    }
}