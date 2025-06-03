import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

class LoadOpcode extends AstNode instanceof TOpcode_load{

    int getSPVarIndex(){
        result = toTreeSitter(this).(Teal::LoadOpcode).getValue().toString().toInt()
    }

    SSAVar getScratchSpaceStoredVariable(){
        result = this.getInfluencingStore().getScratchSpaceStoredVariable()
    }

    StoreOpcode getInfluencingStore(){
        exists(StoreOpcode store | store.getSPVarIndex() = this.getSPVarIndex() and store.reaches(this)
            and store.getBasicBlock().dominates(this.getBasicBlock())
            and not exists(StoreOpcode alt_store | 
                alt_store.getSPVarIndex() = this.getSPVarIndex() and
                store.reaches(alt_store) and
                alt_store.reaches(this) and
                alt_store != store and
                store.getBasicBlock().dominates(alt_store.getBasicBlock()) and alt_store.getBasicBlock().dominates(this.getBasicBlock()))
            and result = store)
    }

    SSAVar getOriginVariable(){
        result = this.getScratchSpaceStoredVariable*() 
            and not result.getDeclarationNode() instanceof LoadOpcode
    }
}

class StoreOpcode extends AstNode instanceof TOpcode_store{
    int getSPVarIndex(){
        result = toTreeSitter(this).(Teal::StoreOpcode).getValue().toString().toInt()
    }

    SSAVar getScratchSpaceStoredVariable(){
        result = this.getConsumedVars()
    }

    predicate isUnivocal(){
        count(this.getScratchSpaceStoredVariable()) = 1
    }
}

