import codeql.teal.ast.AST
import codeql.teal.ast.internal.TreeSitter
import codeql.teal.cfg.BasicBlocks
import codeql.teal.SSA.SSA

/** The `load` opcode: load value from scratch space by index. */
class LoadOpcode extends AstNode instanceof TOpcode_load {
    override int getStackDelta() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }

    int getSPVarIndex() {
        result = toTreeSitter(this).(Teal::LoadOpcode).getValue().toString().toInt()
    }

    SSAVar getScratchSpaceStoredVariable() {
        result = this.getInfluencingStore().getScratchSpaceStoredVariable()
    }

    /**
     * Gets every `StoreOpcode` that may influence the value read by this
     * `load N`. A store "may influence" this load if it writes to the same
     * slot and can reach this load along some CFG path — i.e. there exists
     * an execution in which the value written by that store is the value
     * read here.
     *
     * This is a MAY-reach relation, not a MUST-reach / dominance one:
     *
     *   - In a diamond like
     *         if cond: store 0 (A)
     *         else:    store 0 (B)
     *         load 0
     *     neither A nor B individually dominates the load, but both of them
     *     may supply the value that the load observes at runtime. A dominance
     *     only check would return no influencing store at all and silently
     *     lose both flows.
     *
     *   - BUT we do kill a store whose value is unconditionally overwritten
     *     by a later store on the same slot before the load runs. This is
     *     the purpose of the `not exists(overwrite | ...)` clause below:
     *     a store `result` is excluded when there exists another store
     *     `overwrite` on the same slot such that
     *       - `result.reaches(overwrite)` (so `overwrite` is after `result`),
     *         and
     *       - `overwrite.getBasicBlock().dominates(load)` (so *every* path
     *         from the program entry to the load goes through `overwrite`).
     *     Combining those two facts: every path from `result` to the load
     *     also goes through `overwrite`, so `result`'s value is guaranteed
     *     to be clobbered before the load observes anything.
     *
     * Per-slot isolation is still enforced: we only pair stores and loads
     * that target the same slot index, so a `load 0` is never wired to a
     * `store 1`.
     */
    StoreOpcode getInfluencingStore() {
        result.getSPVarIndex() = this.getSPVarIndex() and
        result.reaches(this) and
        not exists(StoreOpcode overwrite |
            overwrite.getSPVarIndex() = this.getSPVarIndex() and
            overwrite != result and
            result.reaches(overwrite) and
            overwrite.getBasicBlock().dominates(this.getBasicBlock())
        )
    }
}

/** The `store` opcode: store value to scratch space by index. */
class StoreOpcode extends AstNode instanceof TOpcode_store {
    override int getStackDelta() { result = -1 }
    override int getNumberOfConsumedArgs() { result = 1 }

    int getSPVarIndex() {
        result = toTreeSitter(this).(Teal::StoreOpcode).getValue().toString().toInt()
    }

    SSAVar getScratchSpaceStoredVariable() {
        result = this.getConsumedVars()
    }

    predicate isUnivocal() {
        count(this.getScratchSpaceStoredVariable()) = 1
    }
}

/** The `loads` opcode: load value from scratch space by stack index. */
class LoadsOpcode extends AstNode instanceof TOpcode_loads {
    override int getStackDelta() { result = 0 }
    override int getNumberOfConsumedArgs() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `stores` opcode: store value to scratch space by stack index. */
class StoresOpcode extends AstNode instanceof TOpcode_stores {
    override int getStackDelta() { result = -2 }
    override int getNumberOfConsumedArgs() { result = 2 }
}

/** The `gload` opcode: load scratch space value from another transaction in group. */
class GloadOpcode extends AstNode instanceof TOpcode_gload {
    override int getStackDelta() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `gloads` opcode: load scratch space value from another transaction by stack index. */
class GloadsOpcode extends AstNode instanceof TOpcode_gloads {
    override int getStackDelta() { result = 0 }
    override int getNumberOfConsumedArgs() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `gloadss` opcode: load scratch space value from another transaction by stack group and slot. */
class GloadssOpcode extends AstNode instanceof TOpcode_gloadss {
    override int getStackDelta() { result = -1 }
    override int getNumberOfConsumedArgs() { result = 2 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `gaid` opcode: get asset ID created by another transaction in group. */
class GaidOpcode extends AstNode instanceof TOpcode_gaid {
    override int getStackDelta() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `gaids` opcode: get asset ID created by another transaction by stack index. */
class GaidsOpcode extends AstNode instanceof TOpcode_gaids {
    override int getStackDelta() { result = 0 }
    override int getNumberOfConsumedArgs() { result = 1 }
    override int getNumberOfOutputArgs() { result = 1 }
}
