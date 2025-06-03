private import codeql.teal.ast.AST
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.SSA.SSA
private import codeql.teal.ast.internal.TreeSitter

class TInnerTransactionStart = TOpcode_itxn_begin or TOpcode_itxn_next;
class TInnerTransactionEnd = TOpcode_itxn_next or TOpcode_itxn_submit;

class InnerTransactionStart extends AstNode instanceof TInnerTransactionStart{
    InnerTransactionEnd getItxnClosure(){
        this != result and
        this.reaches(result)
    }   
}

class InnerTransactionEnd extends AstNode instanceof TInnerTransactionEnd{
}

class InnerTransactionBegin extends InnerTransactionStart instanceof TOpcode_itxn_begin{
    // AstNode getItxnClosure(){
    //     this.reaches(result) and (result instanceof InnerTransactionSubmit or result instanceof InnerTransactionNext)
    // }
}

class InnerTransactionField extends AstNode instanceof TOpcode_itxn_field{
    // predicate contributesToItxn1(InnerTransactionBegin begin, AstNode itxnClosure){
    //     begin.reaches(this) and this.reaches(itxnClosure) and 
    //     (itxnClosure instanceof InnerTransactionNext or itxnClosure instanceof InnerTransactionSubmit)
    //     and()
    // }

    // predicate contributesToItxn2(InnerTransactionStart begin, InnerTransactionEnd itxnClosure){
    //     //eliminate trivial case itxn_next = itxn_next
    //     begin != itxnClosure and
    //     begin.(AstNode).reaches(this) and this.reaches(itxnClosure)
    //     // and
    //     // (itxnClosure instanceof InnerTransactionNext or itxnClosure instanceof InnerTransactionSubmit)
    // }

    predicate contributesToItxn(InnerTransactionStart begin, InnerTransactionEnd itxnClosure){
        //eliminate trivial case itxn_next = itxn_next
        begin != itxnClosure and
        begin.getItxnClosure() = itxnClosure and
        begin.reaches(this) and this.reaches(itxnClosure)
    
        // and begin.reaches(itxnClosure)
        // and not exists(
        //     InnerTransactionEnd end | begin.reaches(end) and
        //     end != itxnClosure and end != begin and
        //     end.reaches(itxnClosure) and
        //     (
        //         end.getBasicBlock() = itxnClosure.getBasicBlock() and
        //         end.getLineNumber() < itxnClosure.getLineNumber()
        //         or
        //         end.getBasicBlock().dominates(itxnClosure.getBasicBlock())
        //     )
        // )
        // and begin.reaches(itxnClosure)
        // and not exists(
        //     InnerTransactionEnd end | begin.reaches(end) and
        //     end != itxnClosure and end != begin and
        //     end.reaches(itxnClosure)
        //     // end.getBasicBlock().dominates(itxnClosure.getBasicBlock())
        // )
        // and
        // (itxnClosure instanceof InnerTransactionNext or itxnClosure instanceof InnerTransactionSubmit)
    }

    SSAVar getItxnFieldVal(){
        result = this.getConsumedVars()
    }

    string getItxnField(){
        result = toTreeSitter(this).(Teal::ItxnFieldOpcode).getTxnField()
    }
}

class InnerTransactionNext extends InnerTransactionStart, InnerTransactionEnd instanceof TOpcode_itxn_next{
    // AstNode getItxnClosure(){
    //     this.getNextLine().reaches(result) and (result instanceof InnerTransactionSubmit or result instanceof InnerTransactionNext)
    // }
}

class InnerTransactionSubmit extends InnerTransactionEnd instanceof TOpcode_itxn_submit{

    InnerTransactionStart getStart(){
        result.getItxnClosure() = this
    }

    InnerTransactionBegin getItxnBegin(){
        result.getItxnClosure() = this or
        result.getItxnClosure() = this.getItxnNext()
        // exists(InnerTransactionNext next | next.getItxnClosure() = this and result.getItxnClosure() = next)
    }

    InnerTransactionNext getItxnNext(){
        result.getItxnClosure() = this
    }
}

class ItxnFieldName extends string{
    ItxnFieldName(){
        this = "Sender" or this = "Fee" or this = "FirstValid" or 
        this = "FirstValidTime" or this = "LastValid" or this = "Note" or 
        this = "Lease" or this = "Receiver" or this = "Amount" or this = "CloseRemainderTo" or 
        this = "VotePK" or this = "SelectionPK" or this = "VoteFirst" or this = "VoteLast" or 
        this = "VoteKeyDilution" or this = "Type" or this = "TypeEnum" or this = "XferAsset" or 
        this = "AssetAmount" or this = "AssetSender" or this = "AssetReceiver" or 
        this = "AssetCloseTo" or this = "GroupIndex" or this = "TxID" or this = "ApplicationID" or 
        this = "OnCompletion" or this = "NumAppArgs" or this = "NumAccounts" or 
        this = "ApprovalProgram" or this = "ClearStateProgram" or this = "RekeyTo" or 
        this = "ConfigAsset" or this = "ConfigAssetTotal" or this = "ConfigAssetDecimals" or 
        this = "ConfigAssetDefaultFrozen" or this = "ConfigAssetUnitName" or 
        this = "ConfigAssetName" or this = "ConfigAssetURL" or this = "ConfigAssetMetadataHash" or 
        this = "ConfigAssetManager" or this = "ConfigAssetReserve" or this = "ConfigAssetFreeze" or 
        this = "ConfigAssetClawback" or this = "FreezeAsset" or this = "FreezeAssetAccount" or 
        this = "FreezeAssetFrozen" or this = "NumAssets" or this = "NumApplications" or 
        this = "GlobalNumUint" or this = "GlobalNumByteSlice" or this = "LocalNumUint" or 
        this = "LocalNumByteSlice" or this = "ExtraProgramPages" or this = "Nonparticipation" or 
        this = "NumLogs" or this = "CreatedAssetID" or this = "CreatedApplicationID" or 
        this = "LastLog" or this = "StateProofPK" or this = "NumApprovalProgramPages" or 
        this = "NumClearStateProgramPages"
    }
}