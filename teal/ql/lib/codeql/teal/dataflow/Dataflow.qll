private import codeql.dataflow.DataFlow
private import codeql.teal.ast.AST
private import codeql.teal.cfg.CFG::CfgImpl as Cfg
private import codeql.teal.SSA.SSA as Ssa
private import codeql.Locations
// private import codeql.teal.ast.scratchSpace


private module Private {

  cached
  newtype TNode =
  TNoOutputNodes(AstNode n){n.getNumberOfOutputArgs() = 0 and n.getNumberOfConsumedArgs() > 0}
  or
    // or

    // TLoadNode(Cfg::Node n) or
    // TStoreNode(Cfg::Node n) or

    // TExprNode(DataFlowExpr e) or
    // TReturningNode(Cfg::Node n) { n.getAstNode() = any(FunctionDefinition d).getBody() } or
    // TOpcodeNode(Cfg::Node op){op.getAstNode() instanceof TOpcode} or  //TODO: placeholder for now
    TStackVarNode(SSAVar op) or  //TODO: placeholder for now
    TSsaDefinitionNode(Ssa::Definition def) or
    TScratchLoadNode(SSAVar op){
      op.getDeclarationNode() instanceof LoadOpcode or
      op.getDeclarationNode() instanceof LoadsOpcode 
      // or
      // op.getDeclarationNode() instanceof TOpcode_gload or
      // op.getDeclarationNode() instanceof TOpcode_gloads or
      // op.getDeclarationNode() instanceof TOpcode_gloadss
    }
    // or
    // TExitNode(Cfg::Node op){op.getAstNode() instanceof ContractExitOpcode} or
    // TLoadNode(Cfg::Node op){op.getAstNode() instanceof LoadOpcode} or
    // TStoreNode(Cfg::Node op){op.getAstNode() instanceof StoreOpcode}

    // or
    // TParameterNode(Identifier p) { p = any(FunctionDefinition d).getPrototype().getArgument(_) }

  // class DataFlowExpr extends Cfg::Node {
  //   DataFlowExpr() { this.getAstNode() instanceof Expression }
  // }

  // class ParameterPosition extends int {
  //   ParameterPosition() { this = [0, 1] or exists(any(Prototype e).getArgument(this)) }
  // }

  // class ArgumentPosition extends int {
  //   ArgumentPosition() { this = [0, 1] or exists(any(FunctionCallExpression e).getArgument(this)) }
  // }

  // predicate parameterMatch(ParameterPosition ppos, ArgumentPosition apos) { ppos = apos }

  // class DataFlowCall instanceof Cfg::Node {
  //   DataFlowCall() {
  //     super.getAstNode() instanceof FunctionCallExpression or
  //     super.getAstNode() instanceof BinaryOpExpression or
  //     super.getAstNode() instanceof UnaryOpExpression
  //   }

  //   /** Gets a textual representation of this element. */
  //   string toString() { result = super.toString() }

  //   Location getLocation() { result = super.getLocation() }

  //   string getName() {
  //     result = super.getAstNode().(FunctionCallExpression).getCallee().getName() or
  //     result = super.getAstNode().(BinaryOpExpression).getOperator().getName() or
  //     result = super.getAstNode().(UnaryOpExpression).getOperator().getName()
  //   }

  //   DataFlowCallable getEnclosingCallable() { result = super.getScope() }
  // }

//   class DataFlowCallable instanceof Cfg::CfgScope {
//     string toString() { result = super.toString() }

//     Location getLocation() { result = super.getLocation() }

//     string getName() { result = this.(FunctionDefinition).getPrototype().getIdentifier().getName() }
//   }

//   private newtype TDataFlowType = TUnknownDataFlowType()

//   class DataFlowType extends TDataFlowType {
//     string toString() { result = "" }
//   }
}

private module Public {
  private import Private

  class Node extends TNode {
    /** Gets a textual representation of this element. */
    string toString() { none() }

    Location getLocation() { none() }

    abstract AstNode getUnderlyingASTNode();

    /**
     * Holds if this element is at the specified location.
     * The location spans column `startcolumn` of line `startline` to
     * column `endcolumn` of line `endline` in file `filepath`.
     * For more information, see
     * [Locations](https://codeql.github.com/docs/writing-codeql-queries/providing-locations-in-codeql-queries/).
     */
    predicate hasLocationInfo(
      string filepath, int startline, int startcolumn, int endline, int endcolumn
    ) {
      this.getLocation().hasLocationInfo(filepath, startline, startcolumn, endline, endcolumn)
    }
  }



  // class ExprNode extends Node, TExprNode {
  //   private DataFlowExpr expr;

  //   ExprNode() { this = TExprNode(expr) }

  //   Cfg::Node getCfgNode() { result = expr }

  //   override string toString() { result = expr.toString() }

  //   override Location getLocation() { result = expr.getLocation() }
  // }

  class NoOutputNode extends Node, TNoOutputNodes {
    Cfg::Node getCfgNode() { result.getAstNode() = this.getUnderlyingASTNode() }

    override AstNode getUnderlyingASTNode(){
      this = TNoOutputNodes(result)
    }
  }

  // class OpcodeNode extends Node, TOpcodeNode {
  class OpcodeNode extends Node, TStackVarNode {
    // private Cfg::Node expr;
    private SSAVar expr;

    // OpcodeNode() { this = TOpcodeNode(expr) }
    OpcodeNode() { this = TStackVarNode(expr) }

    // Cfg::Node getCfgNode() { result = expr }
    Cfg::Node getCfgNode() { result.getAstNode() = expr.getDeclarationNode() }

    override string toString() { result = expr.toString() }

    override Location getLocation() { result = expr.getLocation() }

    override AstNode getUnderlyingASTNode(){
      result = this.getCfgNode().getAstNode()
    }
  }

  // class ParameterNode extends Node, TParameterNode {
  //   private Identifier parameter;

  //   ParameterNode() { this = TParameterNode(parameter) }

  //   predicate isParameterOf(DataFlowCallable c, ParameterPosition pos) {
  //     parameter = c.(FunctionDefinition).getPrototype().getArgument(pos)
  //   }

  //   override string toString() { result = parameter.toString() }

  //   override Location getLocation() { result = parameter.getLocation() }

  //   Identifier getParameter() { result = parameter }
  // }

  // class ArgumentNode extends ExprNode {
  //   ArgumentNode() {
  //     this.getCfgNode().getAstNode() = any(FunctionCallExpression e).getArgument(_) or
  //     this.getCfgNode().getAstNode() = any(BinaryOpExpression e).getLhs() or
  //     this.getCfgNode().getAstNode() = any(BinaryOpExpression e).getRhs() or
  //     this.getCfgNode().getAstNode() = any(UnaryOpExpression e).getOperand()
  //   }

  //   predicate argumentOf(DataFlowCall call, ArgumentPosition pos) {
  //     this.getCfgNode() = call.(Cfg::Node).getAPredecessor+() and
  //     (
  //       call.(Cfg::Node).getAstNode() =
  //         any(FunctionCallExpression e | e.getArgument(pos) = this.getCfgNode().getAstNode()) or
  //       call.(Cfg::Node).getAstNode() =
  //         any(BinaryOpExpression e |
  //           pos = 0 and e.getLhs() = this.getCfgNode().getAstNode()
  //           or
  //           pos = 1 and e.getRhs() = this.getCfgNode().getAstNode()
  //         ) or
  //       call.(Cfg::Node).getAstNode() =
  //         any(UnaryOpExpression e | pos = 0 and e.getOperand() = this.getCfgNode().getAstNode())
  //     )
  //   }
  // }

  // class ReturnNode extends Node, TReturningNode {
  //   private Cfg::Node node;

  //   ReturnNode() { this = TReturningNode(node) }

  //   ReturnKind getKind() { result = TNormalReturn() }

  //   override string toString() { result = "return " + node.toString() }

  //   override Location getLocation() { result = node.getLocation() }
  // }

  // private newtype TReturnKind = TNormalReturn()

  // abstract class ReturnKind extends TReturnKind {
  //   /** Gets a textual representation of this element. */
  //   abstract string toString();
  // }

  // class NormalReturn extends ReturnKind, TNormalReturn {
  //   override string toString() { result = "return" }
  // }


  class SsaDefinitionNode extends Node, TSsaDefinitionNode {
    Ssa::Definition def;

    SsaDefinitionNode() { this = TSsaDefinitionNode(def) }

    Ssa::Definition asDefinition() { result = def }

    override string toString() { result = def.toString() }

    override Location getLocation() { result = def.getLocation() }

    override AstNode getUnderlyingASTNode(){
      if def instanceof SSAWriteDef then result = def.(SSAWriteDef).getRHS()
      else none() //for now lets leave phi out so its one single result
    
      // else if def instanceof DirectPhi then result = def.(DirectPhi).getOriginatingInput().getDeclarationNode()
      // else result = def.(IndirectPhi).getGenerator().getOriginatingInput().getDeclarationNode()
    }
  }

  predicate isBarrier(Node n){
    exists(AstNode s |
      n.getUnderlyingASTNode() instanceof MatchOpcode or
      n.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS() = s and
      not (s instanceof BuryOpcode or s instanceof DigOpcode or
        s instanceof CoverOpcode or s instanceof UncoverOpcode or
        s instanceof SwapOpcode or s instanceof DupOpcode or
        s instanceof Dup2Opcode or s instanceof DupnOpcode or
        s instanceof FrameDigOpcode or s instanceof FrameBuryOpcode or
        s instanceof RetsubOpcode or
        // `load N` is not a barrier: it is an identity pass-through for the
        // value written by the corresponding `store N`. The connection is
        // added by `scratchBridge` in `localSsaFlowStep`, so letting flow
        // continue through the load's SSAWriteDef makes that bridge
        // transitively composable with the rest of the flow graph.
        s instanceof LoadOpcode)
      )
    or
    // Subroutine entry phis are barriers at the top-level flow: they represent
    // the MERGE of arguments from every caller of the subroutine, so letting
    // flow propagate through one would immediately leak caller A's value into
    // caller B's context (cross-callsite contamination). The top-level flow
    // is therefore forced to STOP at any subroutine boundary; the only way to
    // cross is via `callsubBridge`, which injects per-call-site edges based on
    // a context-specific `SubroutineFlow` analysis. This also generalises to
    // nested subroutines: a nested sub's entry phi is likewise a barrier, and
    // the nested callsub bridge will handle the boundary.
    exists(Subroutine sub |
      n.(SsaDefinitionNode).asDefinition().(DirectPhi).getBasicBlock() = sub.getBasicBlock()
    )
  }

  predicate simpleLocalFlowStep(Node nodeFrom, Node nodeTo) {
    // LocalFlow::localFlowStep(nodeFrom, nodeTo)
    // or
    // not isBarrier(nodeFrom) and
    LocalFlow::localSsaFlowStep(nodeFrom, nodeTo)
  }
}

// private module LocalFlow {
module LocalFlow {
  private import Public
  private import codeql.teal.cfg.BasicBlocks

  // private predicate localSsaFlowStepUseUse(Ssa::Definition def, OpcodeNode nodeFrom, OpcodeNode nodeTo) {
  //   def.adjacentReadPair(nodeFrom.getCfgNode(), nodeTo.getCfgNode())
  // }

  // private predicate localFlowSsaInput(
  //   SsaDefinitionNode nodeFrom, Ssa::Definition def, Ssa::Definition next
  // ) {
  //   exists(BasicBlock bb, int i | def.lastRefRedef(bb, i, next) |
  //     def.definesAt(_, i, bb) and
  //     def = nodeFrom.asDefinition()
  //   )
  // }

  // /**
  //  * Holds if `nodeFrom` is a parameter node, and `nodeTo` is a corresponding SSA node.
  //  */
  // private predicate localFlowSsaParamInput(ParameterNode nodeFrom, SsaDefinitionNode nodeTo) {
  //   nodeTo.asDefinition().definesAt(nodeFrom.getParameter(), _, _)
  // }

  // Strict SSA-level flow through a single opcode.
  //
  // Stack convention (from the original author):
  //   [v3 v2 v1] -> OP -> [v1 v2 v3]
  //   Inputs are numbered from the top of stack (v1 is `inOrd=1`). On exit,
  //   output positions are numbered from the "bottom" (reversed relative to
  //   the physical stack), which is why retsub uses `N+1-inOrd`.
  //
  // CALL-SITE SENSITIVITY:
  //   When the op is `retsub` and `defFrom` is a phi at the subroutine entry
  //   BB, we *block* the propagation. A phi at the subroutine entry merges the
  //   argument values passed in by every caller of that subroutine; if we
  //   allowed it to flow through retsub, the value would then be visible at
  //   every caller's continuation phi, meaning caller A's arg would appear to
  //   flow into caller B's post-callsub consumers. That is the "cross-callsite
  //   contamination" bug.
  //
  //   Instead, for caller-arg flow we use `callsubBridge` (below), which
  //   directly connects caller A's arg to caller A's continuation phi (and
  //   nothing else) — so it's inherently call-site-specific.
  //
  //   For flow that *originates inside* the subroutine body (for example
  //   `global LatestTimestamp; retsub`), the source is an SSAWriteDef of an
  //   internal opcode, NOT an entry phi, so the block above does not apply
  //   and the flow propagates naturally through retsub to every caller's
  //   continuation phi. This is exactly the semantics we want: an internally-
  //   produced value IS returned to whoever called the subroutine.
  predicate defSSAFlowThroughOp(Definition defFrom, AstNode op, Definition defTo){
    op = defTo.(SSAWriteDef).getRHS() and
    op.getAnOutputVar().toDef() = defTo and
    op.getConsumedValues() = defFrom and
    exists(int inOrd, int outOrd |
      inOrd = op.getStackInputOrderByDef(defFrom) and
      outOrd = defTo.(SSAWriteDef).getVar().getInternalOutputIndex()
      and(

        op instanceof DigOpcode and (
          inOrd = op.getNumberOfConsumedArgs() and (outOrd = op.getNumberOfOutputArgs() or outOrd = 1)
          or
          inOrd in [1 .. op.getNumberOfConsumedArgs()-1] and outOrd = inOrd+1
        )
        or
        
        //TODO: test
        op instanceof BuryOpcode and (
          inOrd = 1 and outOrd = op.getNumberOfOutputArgs()
          or
          inOrd in [1 .. op.getNumberOfConsumedArgs()-1] and outOrd = inOrd+1
        )
        or

        op instanceof DupOpcode and(
          inOrd = 1 and outOrd in [1..2]
        )
        or

        op instanceof Dup2Opcode and (
          inOrd = 1 and (outOrd = 1 or outOrd = 3)
          or inOrd = 2 and (outOrd = 2 or outOrd = 4)
        )
        or

        op instanceof DupnOpcode and (
          inOrd = 1 and outOrd in [1 .. op.getNumberOfOutputArgs()]
        )
        or

        op instanceof SwapOpcode and (
          inOrd = 1 and outOrd = 2
          or
          inOrd = 2 and outOrd = 1
        )
        or

        op instanceof CoverOpcode and (
          inOrd = 1 and outOrd = op.getNumberOfOutputArgs()
          or
          inOrd in [2 .. op.getNumberOfConsumedArgs()] and outOrd = inOrd - 1
        )
        or

        op instanceof UncoverOpcode and (
          inOrd = op.getNumberOfConsumedArgs() and outOrd = 1
          or
          inOrd in [1 .. op.getNumberOfConsumedArgs()-1] and outOrd = inOrd + 1
        )
        or

        op instanceof FrameDigOpcode and (
          inOrd = op.getNumberOfConsumedArgs() and (outOrd = op.getNumberOfOutputArgs() or outOrd = 1)
          or
          inOrd in [1 .. op.getNumberOfConsumedArgs()-1] and outOrd = inOrd+1
        )
        or

        //TODO: test
        op instanceof FrameBuryOpcode and (
          inOrd = 1 and outOrd = op.getNumberOfOutputArgs()
          or
          inOrd in [1 .. op.getNumberOfConsumedArgs()-1] and outOrd = inOrd+1
        )
        or

        // retsub: conceptually, the top N values of the stack at retsub time
        // become the N return values. The "reversed" convention means
        // inOrd=1 (topmost input) maps to outOrd=N (bottommost output), hence
        // `outOrd = N + 1 - inOrd` (both are 1-based).
        //
        // Note that we allow any `defFrom` here, including the subroutine
        // entry phi. The call-site-sensitivity guarantee is instead enforced
        // by `isBarrier` marking subroutine entry phis as barriers, which
        // prevents the recursive `localFlow` from routing a caller arg
        // through `entry_phi -> retsub_out -> contPhi` transitively.
        op instanceof RetsubOpcode and
        (
          inOrd in [1 .. op.(RetsubOpcode).getAffectingProto().getNumberOfSubroutineOutputArgs()] and
          outOrd = op.(RetsubOpcode).getAffectingProto().getNumberOfSubroutineOutputArgs() + 1 - inOrd
        )

        //TODO: complete with ALL ops that allow a full value to flow through into
        // the stack!!
      )
    )
  }

  /**
   * Callsub bridge: at a callsub site, connect a caller arg to the
   * corresponding continuation phi if SubroutineFlow shows the matching
   * subroutine entry phi reaches the matching retsub output.
   *
   * - The caller arg is an SSAVar in the caller's BB at stack position `inIdx`.
   * - The continuation phi is a DirectPhi in the BB starting after the callsub,
   *   at initialStackIndex `outIdx`.
   * - The bridge is added if SubroutineFlow shows the entry phi at position
   *   `inIdx` reaches the retsub output at position `outIdx` within the
   *   called subroutine.
   *
   * This is call-site sensitive: each callsub gets its own bridge edges,
   * connecting only that callsub's args to that callsub's continuation phis.
   */
  predicate callsubBridge(Node nodeFrom, Node nodeTo) {
    exists(
      CallsubOpcode cs, Subroutine sub, int inIdx, int outIdx,
      SSAVar argVar, DirectPhi contPhi, DirectPhi entryPhi, SSAVar retsubOut,
      Node entryNode, Node retsubOutNode
    |
      sub = cs.getSubroutine() and
      // Caller's arg at input position inIdx
      argVar.getBasicBlock() = cs.getBasicBlock() and
      argVar.outStackOrder() = inIdx and
      nodeFrom.(SsaDefinitionNode).asDefinition() = argVar.toDef() and
      // Caller's continuation phi at output position outIdx (the BB after callsub)
      contPhi.getBasicBlock() = cs.getNextLine().getBasicBlock() and
      contPhi.getInitialStackIndex() = outIdx and
      nodeTo.(SsaDefinitionNode).asDefinition() = contPhi and
      // Subroutine entry phi at position inIdx
      entryPhi.getBasicBlock() = sub.getBasicBlock() and
      entryPhi.getInitialStackIndex() = inIdx and
      entryNode.(SsaDefinitionNode).asDefinition() = entryPhi and
      // Retsub output at position outIdx
      retsubOut.getDeclarationNode() = sub.getRetsubOpcode() and
      retsubOut.getInternalOutputIndex() = outIdx and
      retsubOutNode.(SsaDefinitionNode).asDefinition() = retsubOut.toDef() and
      // The mapping must hold inside the subroutine
      SubroutineFlow::flowThroughSubroutine(entryNode, retsubOutNode)
    )
  }

  /**
   * Scratch-slot bridge: connects the value consumed by a `store N` to the
   * value produced by each `load N` it may influence.
   *
   * This handles the immediate form only (`store N` / `load N` where the
   * slot index is a compile-time constant). The dynamic forms (`stores` /
   * `loads`, which pop the slot index off the stack) are intentionally out
   * of scope for now — they require resolving the index at analysis time.
   *
   * The edge added is `stored_value_def -> load_output_def`. It is a direct
   * SSA-to-SSA connection — no stack manipulation involved — because the
   * slot index acts as a named channel between the two opcodes. In
   * `localFlow` this lets flow "skip" the stack and cross through scratch.
   *
   * Per-slot separation and the may-influence relation are both delegated
   * to `LoadOpcode.getInfluencingStore()` (see ScratchSpace.qll).
   */
  predicate scratchBridge(Node nodeFrom, Node nodeTo) {
    exists(StoreOpcode store, LoadOpcode load, SSAVar storedVar, SSAVar loadedVar |
      load.getInfluencingStore() = store and
      // Source side: the SSAVar whose value the store consumed from the stack.
      storedVar = store.getScratchSpaceStoredVariable() and
      nodeFrom.(SsaDefinitionNode).asDefinition() = storedVar.toDef() and
      // Sink side: the SSAVar produced by the load.
      loadedVar = load.getAnOutputVar() and
      nodeTo.(SsaDefinitionNode).asDefinition() = loadedVar.toDef()
    )
  }

  /**
   * Holds if there is a local flow step from `nodeFrom` to `nodeTo` involving
   * SSA.
   */
  predicate localSsaFlowStep(Node nodeFrom, Node nodeTo) {

    defSSAFlowThroughOp(
      nodeFrom.(SsaDefinitionNode).asDefinition(),
      nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS(),
      nodeTo.(SsaDefinitionNode).asDefinition() //this one should always be a SSAWrite
      //probably can get rid of the op in the middle
      )
    or

    //TODO: this should be solved in the "normal" side, as it goes from SSA to "out"
    //[ssawrite|direct phi|indirect phi] -> use
    // The stack-manipulation exclusion below avoids creating duplicate edges
    // for operations that are already handled by `defSSAFlowThroughOp`.
    // Retsub is not in this list because propagation through retsub is now
    // uniformly handled: retsub->caller flows via the standard ssawrite->phi
    // branch (legal for internal sources), while caller->retsub leaks are
    // blocked by the subroutine-entry-phi barrier in `isBarrier` above.
    not (
      nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_dig
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_bury
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_cover
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof UncoverOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof SwapOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_dup
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof Dup2Opcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof DupnOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof FrameBuryOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof FrameDigOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof RetsubOpcode
    ) and
    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    //(d)phi -> ssa_write flow
    nodeFrom.(SsaDefinitionNode).asDefinition().(DirectPhi) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    //(i)phi -> ssa_write flow
    nodeFrom.(SsaDefinitionNode).asDefinition().(IndirectPhi) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    //ssawrite to phi (direct)
    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef) =
    nodeTo.(SsaDefinitionNode).asDefinition().(DirectPhi).getOriginatingInput().toDef()
    or

    //phi-to-phi flow (first phi can be d|i, second phi is always indirect)
    nodeFrom.(SsaDefinitionNode).asDefinition() =
    nodeTo.(SsaDefinitionNode).asDefinition().(IndirectPhi).getGenerator()

    // No output nodes should be sinks: they don't emit vars
    // but do consume them
    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getVar() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode().getConsumedVars()
    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(DirectPhi).getConsumedBy() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode()
    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(IndirectPhi).getConsumedBy() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode()
    or

    // Callsub bridge: the ONLY way caller-arg flow crosses a subroutine
    // boundary. `isBarrier` marks subroutine entry phis as barriers, which
    // prevents the recursive `localFlow` from transitively routing through
    // them. `callsubBridge` then adds a direct, per-callsite edge from each
    // caller arg to its own continuation phi, using SubroutineFlow to verify
    // the subroutine's input/output mapping. Internal-source flows (like
    // `global; retsub`) do not go through any entry phi, so they propagate
    // through retsub naturally via the standard SSA branches above.
    callsubBridge(nodeFrom, nodeTo)
    or

    // Scratch-slot bridge: `store N` feeds every `load N` that it influences
    // (see `scratchBridge` above). This is a direct SSA-to-SSA channel that
    // bypasses the stack entirely and keeps per-slot flows independent.
    scratchBridge(nodeFrom, nodeTo)
  }

  pragma[nomagic]
  predicate localFlowStep(Node nodeFrom, Node nodeTo) {
    nodeFrom.(OpcodeNode).getCfgNode().getAstNode().getConsumedBy(_) = 
    nodeTo.(OpcodeNode).getCfgNode().getAstNode()
  }

  // pragma[nomagic]
  // predicate localFlow(Node source, Node sink) {
  //   simpleLocalFlowStep*(source, sink)
  // }

  //not that this flow model does not implement taint:
  // either a source flows fully through an intermediate node towards the sink,
  // or it is modified in any way and thus "stopped"/"consumed".
  //The isBarrier() predicate could be made parametrisable so as to
  // be able to define more complex models (e.g. sanitization).
  pragma[nomagic]
  predicate localFlow(Node source, Node sink) {
    //all nodes flow with themselves
    source = sink
    or
    //For the last step we don't check for barrier since we arrived to the sink
    simpleLocalFlowStep(source, sink)
    or
    //recursive step: there is a "mid" node we may go through
    exists(Node mid |
      (simpleLocalFlowStep(source, mid) and
      mid != source and mid != sink and
      not isBarrier(mid) and localFlow(mid, sink))
    )
  }
}

/**
 * Subroutine-aware flow analysis. Used by `LocalFlow::callsubBridge` to
 * determine, for a given subroutine, which input argument positions flow to
 * which return value positions. Unlike the top-level LocalFlow, it does NOT
 * treat subroutine entry phis as barriers, so it can propagate from an entry
 * phi (representing an argument) all the way through the subroutine body to
 * a retsub output.
 *
 * This analysis is context-agnostic: it answers "does the subroutine's logic
 * route input #i to output #j?" without regard to which specific caller is
 * asking. The per-call-site routing is applied afterwards by `callsubBridge`,
 * which uses the answer from here to add per-caller edges in `LocalFlow`.
 */
module SubroutineFlow {
  private import Public
  private import codeql.teal.cfg.BasicBlocks

  /**
   * SSA flow step reused from LocalFlow's building blocks. The key difference
   * is that SubroutineFlow's `flowThroughSubroutine` (below) does not apply
   * the subroutine-entry-phi barrier, so flow can enter and leave a subroutine
   * freely — which is what we need to compute the input/output routing.
   */
  predicate localSsaFlowStep(Node nodeFrom, Node nodeTo) {

    LocalFlow::defSSAFlowThroughOp(
      nodeFrom.(SsaDefinitionNode).asDefinition(),
      nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS(),
      nodeTo.(SsaDefinitionNode).asDefinition()
      )
    or

    not (
      nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_dig
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_bury
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_cover
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof UncoverOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof SwapOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof TOpcode_dup
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof Dup2Opcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof DupnOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof FrameBuryOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof FrameDigOpcode
      or nodeTo.(SsaDefinitionNode).getUnderlyingASTNode() instanceof RetsubOpcode
    )
    and
    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    nodeFrom.(SsaDefinitionNode).asDefinition().(DirectPhi) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    nodeFrom.(SsaDefinitionNode).asDefinition().(IndirectPhi) =
    nodeTo.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getRHS().getConsumedValues()
    or

    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef) =
    nodeTo.(SsaDefinitionNode).asDefinition().(DirectPhi).getOriginatingInput().toDef()
    or

    nodeFrom.(SsaDefinitionNode).asDefinition() =
    nodeTo.(SsaDefinitionNode).asDefinition().(IndirectPhi).getGenerator()

    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(SSAWriteDef).getVar() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode().getConsumedVars()
    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(DirectPhi).getConsumedBy() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode()
    or
    nodeFrom.(SsaDefinitionNode).asDefinition().(IndirectPhi).getConsumedBy() =
    nodeTo.(NoOutputNode).getUnderlyingASTNode()
  }

  predicate simpleLocalFlowStep(Node nodeFrom, Node nodeTo) {
    localSsaFlowStep(nodeFrom, nodeTo)
  }

  /**
   * Subroutine-aware flow closure. Used to determine, for a given subroutine,
   * which input argument positions flow to which return value positions.
   *
   * Critically, this predicate does NOT consider subroutine entry phis to be
   * barriers (the top-level LocalFlow does). That allows us to start at an
   * entry phi representing "input at position i" and propagate all the way
   * to a retsub output representing "return value at position j" — exactly
   * the question that `callsubBridge` needs to answer.
   *
   * This is context-agnostic (doesn't know about a specific caller) and is
   * safe to recurse: if the analyzed subroutine itself makes a nested
   * callsub, the nested subroutine's entry phi is also not a barrier here,
   * so the flow passes through it naturally inside SubroutineFlow.
   */
  pragma[nomagic]
  predicate flowThroughSubroutine(Node source, Node sink) {
    source = sink
    or
    simpleLocalFlowStep(source, sink)
    or
    exists(Node mid |
      simpleLocalFlowStep(source, mid) and
      mid != source and mid != sink and
      // Note: we deliberately do NOT call `Public::isBarrier(mid)` here,
      // because that predicate marks subroutine entry phis as barriers
      // (a top-level-only concern). Inside a subroutine analysis we must
      // be able to cross those phis, otherwise we could never connect an
      // argument slot to a retsub output slot.
      flowThroughSubroutine(mid, sink)
    )
  }
}

// private module Implementation implements InputSig {
//   import Public
//   import Private

// //   class OutNode extends ExprNode {
// //     private DataFlowCall call;

// //     OutNode() { call = this.getCfgNode() }

// //     DataFlowCall getCall(ReturnKind kind) {
// //       result = call and
// //       kind instanceof NormalReturn
// //     }
// //   }

// //   class PostUpdateNode extends Node {
// //     PostUpdateNode() { none() }

// //     Node getPreUpdateNode() { none() }
// //   }

// //   class CastNode extends Node {
// //     CastNode() { none() }
// //   }

// //   predicate isParameterNode(ParameterNode p, DataFlowCallable c, ParameterPosition pos) {
// //     p.isParameterOf(c, pos)
// //   }

// //   predicate isArgumentNode(ArgumentNode arg, DataFlowCall call, ArgumentPosition pos) {
// //     arg.argumentOf(call, pos)
// //   }

// //   DataFlowCallable nodeGetEnclosingCallable(Node node) {
// //     node = TExprNode(any(DataFlowExpr e | result = e.getScope())) or
// //     node = TReturningNode(any(Cfg::Node n | result = n.getScope())) or
// //     node = TSsaDefinitionNode(any(Ssa::Definition def | result = def.getBasicBlock().getScope())) or
// //     node =
// //       TParameterNode(any(Identifier p |
// //           p = result.(FunctionDefinition).getPrototype().getArgument(_)
// //         ))
// //   }

// //   DataFlowType getNodeType(Node node) { any() }

// //   predicate nodeIsHidden(Node node) { none() }

// //   /** Gets the node corresponding to `e`. */
// //   Node exprNode(DataFlowExpr e) { result = TExprNode(e) }

// //   /** Gets a viable implementation of the target of the given `Call`. */
// //   DataFlowCallable viableCallable(DataFlowCall c) {
// //     // TODO: improve to cover redefined functions
// //     c.getName() = result.getName()
// //   }

// //   /**
// //    * Holds if the set of viable implementations that can be called by `call`
// //    * might be improved by knowing the call context.
// //    */
// //   predicate mayBenefitFromCallContext(DataFlowCall call, DataFlowCallable c) { none() }

// //   /**
// //    * Gets a viable dispatch target of `call` in the context `ctx`. This is
// //    * restricted to those `call`s for which a context might make a difference.
// //    */
// //   DataFlowCallable viableImplInCallContext(DataFlowCall call, DataFlowCall ctx) { none() }

// //   /**
// //    * Gets a node that can read the value returned from `call` with return kind
// //    * `kind`.
// //    */
// //   OutNode getAnOutNode(DataFlowCall call, ReturnKind kind) { call = result.getCall(kind) }

// //   string ppReprType(DataFlowType t) { none() }

// //   bindingset[t1, t2]
// //   predicate compatibleTypes(DataFlowType t1, DataFlowType t2) { t1 = t2 }

// //   predicate typeStrongerThan(DataFlowType t1, DataFlowType t2) { none() }

// //   private newtype TContent = TNoContent() { none() }

// //   class Content extends TContent {
// //     /** Gets a textual representation of this element. */
// //     string toString() { none() }
// //   }

// //   predicate forceHighPrecision(Content c) { none() }

// //   private newtype TContentSet = TNoContentSet() { none() }

// //   /**
// //    * An entity that represents a set of `Content`s.
// //    *
// //    * The set may be interpreted differently depending on whether it is
// //    * stored into (`getAStoreContent`) or read from (`getAReadContent`).
// //    */
// //   class ContentSet extends TContentSet {
// //     /** Gets a textual representation of this element. */
// //     string toString() { none() }

// //     /** Gets a content that may be stored into when storing into this set. */
// //     Content getAStoreContent() { none() }

// //     /** Gets a content that may be read from when reading from this set. */
// //     Content getAReadContent() { none() }
// //   }

// //   private newtype TContentApprox = TNoContentApprox() { none() }

// //   class ContentApprox extends TContentApprox {
// //     /** Gets a textual representation of this element. */
// //     string toString() { none() }
// //   }

// //   ContentApprox getContentApprox(Content c) { none() }

// //   /**
// //    * Holds if data can flow from `node1` to `node2` through a non-local step
// //    * that does not follow a call edge. For example, a step through a global
// //    * variable.
// //    */
// //   predicate jumpStep(Node node1, Node node2) { none() }

// //   /**
// //    * Holds if data can flow from `node1` to `node2` via a read of `c`.  Thus,
// //    * `node1` references an object with a content `c.getAReadContent()` whose
// //    * value ends up in `node2`.
// //    */
// //   predicate readStep(Node node1, ContentSet c, Node node2) { none() }

// //   /**
// //    * Holds if data can flow from `node1` to `node2` via a store into `c`.  Thus,
// //    * `node2` references an object with a content `c.getAStoreContent()` that
// //    * contains the value of `node1`.
// //    */
// //   predicate storeStep(Node node1, ContentSet c, Node node2) { none() }

// //   /**
// //    * Holds if values stored inside content `c` are cleared at node `n`. For example,
// //    * any value stored inside `f` is cleared at the pre-update node associated with `x`
// //    * in `x.f = newValue`.
// //    */
// //   predicate clearsContent(Node n, ContentSet c) { none() }

// //   /**
// //    * Holds if the value that is being tracked is expected to be stored inside content `c`
// //    * at node `n`.
// //    */
// //   predicate expectsContent(Node n, ContentSet c) { none() }

// //   /**
// //    * Holds if the node `n` is unreachable when the call context is `call`.
// //    */
// //   predicate isUnreachableInCall(Node n, DataFlowCall call) { none() }

// //   /**
// //    * Holds if flow is allowed to pass from parameter `p` and back to itself as a
// //    * side-effect, resulting in a summary from `p` to itself.
// //    *
// //    * One example would be to allow flow like `p.foo = p.bar;`, which is disallowed
// //    * by default as a heuristic.
// //    */
// //   predicate allowParameterReturnInSelf(ParameterNode p) { none() }

// //   private newtype TLambdaCallKind = TNone()

// //   class LambdaCallKind = TLambdaCallKind;

// //   /** Holds if `creation` is an expression that creates a lambda of kind `kind` for `c`. */
// //   predicate lambdaCreation(Node creation, LambdaCallKind kind, DataFlowCallable c) { none() }

// //   /** Holds if `call` is a lambda call of kind `kind` where `receiver` is the lambda expression. */
// //   predicate lambdaCall(DataFlowCall call, LambdaCallKind kind, Node receiver) { none() }

// //   /** Extra data-flow steps needed for lambda flow analysis. */
// //   predicate additionalLambdaFlowStep(Node nodeFrom, Node nodeTo, boolean preservesValue) { none() }

// //   /**
// //    * Gets an additional term that is added to the `join` and `branch` computations to reflect
// //    * an additional forward or backwards branching factor that is not taken into account
// //    * when calculating the (virtual) dispatch cost.
// //    *
// //    * Argument `arg` is part of a path from a source to a sink, and `p` is the target parameter.
// //    */
// //   int getAdditionalFlowIntoCallNodeTerm(ArgumentNode arg, ParameterNode p) { none() }

// //   predicate golangSpecificParamArgFilter(DataFlowCall call, ParameterNode p, ArgumentNode arg) {
// //     any()
// //   }
// }

module Dataflow {
  // import DataFlowMake<Implementation>
  import Public
}