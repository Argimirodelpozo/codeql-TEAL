private import codeql.teal.cfg.BasicBlocks
private import codeql.Locations
private import codeql.teal.cfg.CFG as Cfg
private import codeql.teal.ast.AST
private import codeql.teal.ast.IntegerConstants
private import codeql.teal.ast.ScratchSpace
private import codeql.teal.ast.Transaction
private import codeql.teal.ast.Global
// private import codeql.teal.SSA.SSA

// class AVMBool extends int{
//   AVMBool(){this = 0 or this = 1}
// }

// class AVMByes extends string{
//   AVMBytes(){this.length() <= 4096}
// }


// private newtype TDefinition = 
//   TWriteDef(BasicBlock bb, int bbi, int varInternalIdx, AstNode n){
//   n = bb.getNode(bbi).getAstNode() and
//   bbi in [0 .. bb.length()-1] and
//   varInternalIdx in [1 .. bb.getNode(bbi).getAstNode().getNumberOfOutputArgs()]
//   }
//   or TPhiNode(BasicBlock bb, int stackOrd, boolean comesFromVars){
//   exists (StackVar v | v.getDeclarationNode().getBasicBlock() = bb.getAPredecessor() and 
//     v.reachesEndOfOriginBB() and stackOrd = v.outStackOrder() and comesFromVars = true)
//     or exists(PhiNode n, BasicBlock b, int ord| b = bb.getAPredecessor() and
//       n = TPhiNode(b, ord, _) and not exists(phiNodeGetsConsumedBy(ord, b)) and comesFromVars = false
//       and stackOrd = 
//       ord - strictcount(int k | k in [1 .. ord - 1] and 
//         exists(phiNodeGetsConsumedBy(k, b)))
//       )
//   }
//   // or TPhiNode(BasicBlock bb, int stackOrd, boolean comesFromVars){
//   //   exists (SSAWriteDefinition v | v.getDeclarationNode().getBasicBlock() = bb.getAPredecessor() and 
//   //     not exists(writeDefGetsConsumedBy(stackOrd, v.getDeclarationNode(), v.getBasicBlock())) 
//   //     and stackOrd = v.outStackOrder() and comesFromVars = true)
//   //     or exists(PhiNode n, BasicBlock b| b = bb.getAPredecessor() and
//   //       n = TPhiNode(b, stackOrd, _) and not exists(phiNodeGetsConsumedBy(stackOrd, b)) and comesFromVars = false)
//   //   }


// // int computeStackOrderForPhi(BasicBlock originalBB, int originalStackOrder, BasicBlock currentBB){
// //   result = originalStackOrder - strictcount(int k | k in [1 .. originalStackOrder - 1] and 
// //     exists(phiNodeGetsConsumedBy(k, originalBB)))
// // }


// int stackConsumption(BasicBlock bb){
//   result = sum(AstNode n | n = bb.getANode().getAstNode() | n.getNumberOfConsumedArgs())                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
// }

// int stackContribution(BasicBlock bb){
//   result = sum(AstNode n | n = bb.getANode().getAstNode() | n.getNumberOfOutputArgs())
// }

// cached
// int stackDelta(BasicBlock bb){
//   result = stackContribution(bb) - stackConsumption(bb)
// }


// int stackAtBeginning(BasicBlock bb){

//   if not exists(bb.getAPredecessor()) then result = 0
//   else
//     result = max(sum(stackDelta(bb.getAPredecessor*())))
// }


// // int stackAtBeginning_aux(BasicBlock current, BasicBlock target){
// //   current != target and
// //   result = stackDelta(current) + 
// //     stackAtBeginning_aux(current.getASuccessor(), target)
// //   or 
// //   current = target and result = 0
// // }

// // int stackAtBeginning(BasicBlock bb){
// //   result = stackAtBeginning_aux(bb.getScope().(Program).getChild(0).getBasicBlock(), bb)
// // }



// abstract class Definition extends TDefinition{
//   abstract string toString();

//   abstract Location getLocation();
// }


// class PhiNode extends Definition instanceof TPhiNode{

//   BasicBlock getBasicBlock(){TPhiNode(result, _, _) = this}
//   int getIndexInPreStack(){
//     exists(boolean c | TPhiNode(_, result, c) = this and c = true) or
//     exists(boolean c, int j, int k | TPhiNode(_, k, c) = this and c = false
//       // and j = max(PhiNode n, int h | n.getBasicBlock() = this.getBasicBlock() and n = TPhiNode(n.getBasicBlock(), h ,true) | h)
//       and j = count(PhiNode n | n.getBasicBlock() = this.getBasicBlock() and n = TPhiNode(n.getBasicBlock(), _ ,true))
//       and result = j+k)
//   }
//   // Definition getOrigin(){TPhiNode(result) = this}

//   // //how many phis includes total number (valid and invalid)
//   // int howManyPhis(){
//   //   result = count(PhiNode n | n.getBasicBlock() = this.getBasicBlock())
//   // }

//   // int getID(){
//   //   exists(PhiNode phi | phi.getBasicBlock() = this.getBasicBlock().getAPredecessor() and 
//   //     rank[h]())
//   // }

//   // StackVar getAnInput_var(){result = rank[this.getIndexInPreStack()]
//   //   (StackVar v | v = this.getBasicBlock().getAPredecessor().getANode().getAstNode().getAnOutputVar() and 
//   //     v.reachesEndOfOriginBB() |
//   //   v order by v.getBBI())}

//   predicate hasInputFromBlock(BasicBlock b){
//     b.getASuccessor() = this.getBasicBlock() and 
//     exists(StackVar v | v.reachesEndOfOriginBB()) or
//     exists(PhiNode n | n.reachesEndOfOriginBB())
//   }

//   // Definition getInput(int i){
//   //   result = 
//   // }

//   PhiNode getAnInput(){result = rank[this.getIndexInPreStack()]
//     (PhiNode n | this.getBasicBlock().getAPredecessor() = n.getBasicBlock() and 
//     n.reachesEndOfOriginBB() | n order by n.getIndexInPreStack())}

//   Definition getAnInput2(){result = rank[this.getIndexInPreStack()]
//       (PhiNode n | this.getBasicBlock().getAPredecessor() = n.getBasicBlock() and 
//       n.reachesEndOfOriginBB() | n order by n.getIndexInPreStack()) or
//       result = rank[this.getIndexInPreStack()]
//       (StackVar n | this.getBasicBlock().getAPredecessor() = n.getBasicBlock() and 
//       n.reachesEndOfOriginBB() | n.toWriteDef() order by n.outStackOrder())
//     }

//     override string toString(){
//       // if 
//       // this = TPhiNode(_, _, false) 
//       // then
//         result = "phi" + this.getBasicBlock().getFirstNode().getAstNode().getLineNumber() 
//           + "_" + this.getIndexInPreStack()
//       // else 
//       //   exists(StackVar v | v.reachesEndOfOriginBB() and
//       //   result = "phi_" + this.getIndexInPreStack() + " = PHI(" + 
//       //   v + " " + v.getLineNumber() + ")")
//     }

//     // Location showAllInput(){
//     //   exists(StackVar v| v.reachesEndOfOriginBB() 
//     //   and v.getBasicBlock() = this.getBasicBlock().getAPredecessor() | result = v.getLocation())
//     //   // result = concat(StackVar v | v.reachesEndOfOriginBB() 
//     //   //   and v.getBasicBlock() = this.getBasicBlock().getAPredecessor() | v.toString(), " ")
//     // }
  
//     override Location getLocation(){result = this.getBasicBlock().getLocation()}

//     /** Holds if `(this, v)` reaches the end of its origin basic block. */
//   predicate reachesEndOfOriginBB() {
//     not exists(this.getConsumedBy())
//   }

//   cached
//   AstNode getConsumedBy(){
//       result = rank[1](AstNode end|
//           end = this.getBasicBlock().getANode().getAstNode() and
//           this.getIndexInPreStack() + getPartialStackSizeBeforeOutput(end.getBasicBlock().getFirstNode().getAstNode(), end) <= 0
//           | end order by end.getLineNumber()
//       )
//   }
// }

// class SSAWriteDefinition extends Definition instanceof TWriteDef{

//   BasicBlock getBasicBlock(){this = TWriteDef(result, _, _, _)}
//   int getBasicBlockIndex(){this = TWriteDef(_, result, _, _)}
//   int getVarInternalIndex(){this = TWriteDef(_, _, result, _)}
//   AstNode getDeclarationNode(){
//     this = TWriteDef(_, _, _, result)
//   }

//     /** Holds if `(this, v)` reaches the end of its origin basic block. */
//     predicate reachesEndOfOriginBB() {
//       not exists(writeDefGetsConsumedBy(this.getVarInternalIndex(), this.getDeclarationNode(), this.getBasicBlock())) 
//       // not exists(this.getDeclarationNode().getConsumedBy_new(this.getVarInternalIndex()))
//   }

//   int outStackOrder(){
//     this = rank[result](SSAWriteDefinition v | 
//       // this.getDeclarationNode().getBasicBlock().getANode().getAstNode().getAnOutputVar_new() = v 
//       // and 
//       v.reachesEndOfOriginBB() | v order by v.getDeclarationNode().getLineNumber() desc)
//   }

//   override string toString(){result = "out(" + this.getDeclarationNode() + ")_" + this.getVarInternalIndex()}

//   override Location getLocation(){
//     result = this.getDeclarationNode().getLocation()
//   }
// }

newtype TDefinition = 
  TSSAVar(StackVar v) or
  TDirectPhi(int varIndex, BasicBlock bb){
    exists(StackVar v | v.reachesEndOfOriginBB()
    and bb = v.getBasicBlock().getASuccessor() and
    varIndex = v.outStackOrder())
  } or
  TIndirectPhi(int varIndex, BasicBlock bb){
    exists(TDirectPhi phi, int k, BasicBlock b | 
      phi = TDirectPhi(k, b) and varIndex = phiNodeExitIndex(k, b) and
      bb = b.getASuccessor())
      or not exists(TDirectPhi phi, int k, BasicBlock b | 
        phi = TDirectPhi(k, b) and varIndex = phiNodeExitIndex(k, b) and
        bb = b.getASuccessor()) and
      exists(TIndirectPhi phi, int k, BasicBlock b | phi = TIndirectPhi(k, b) and
        bb = b.getASuccessor() and varIndex = phiNodeExitIndex(k, b) 
        // and exists(phi.getGenerator())
      )
  }

abstract class Definition extends TDefinition{
  abstract string toString();

  abstract Location getLocation();

  abstract int getOrd();

  // predicate definesAt(StackVar v, int i, BasicBlock bb){
  //   this instanceof SSAWriteDef and v.toDef() = this 
  //     and v.getDeclarationNode() = bb.getNode(i).getAstNode() or
  //   this instanceof DirectPhi and i = -1 and this.(DirectPhi).getBasicBlock() = bb
  //     and v.getBasicBlock() = bb and v.getDeclarationNode() = bb.getFirstNode().getAstNode() 
  //     and v.getInternalOutputIndex() = this.(DirectPhi).getInitialStackIndex()
  //     or
  //   this instanceof IndirectPhi and i = -1 and this.(IndirectPhi).getBasicBlock() = bb
  //     and v.getBasicBlock() = bb and v.getDeclarationNode() = bb.getFirstNode().getAstNode()
  //     and v.getInternalOutputIndex() = this.(IndirectPhi).getInitialStackIndex()
  // }
}

// AVMIntType extends string{
//   AVMIntType(){this.char in "0123456789"}
// }

// newtype AVMIntType = exists string t | t.
// newtype AVMBytesType = string;

// newtype AVMType = AVMIntType | AVMBytesType;

class SSAWriteDef extends Definition instanceof TSSAVar{
  // SSAWriteDef(){this.internalOutputInd() = v.getInternalOutputIndex() and this = TSSAVar(v.getInternalOutputIndex(), v.getDeclarationNode())}
  SSAWriteDef(){
    exists(StackVar v |
      this = TSSAVar(v)
    )
  }

  // int internalOutputInd(){this = TSSAVar(result, _, v)}

  // Write definition identifier.
  // "var", effective line number, declaration node, and finally (internal) output index 
  override string toString(){
    result = "var_" + "L" + 
    this.getVar().getDeclarationNode().getLineNumber() + "_" + 
    this.getVar().getDeclarationNode() + "_" + 
    this.getVar().getInternalOutputIndex()
  }

  override Location getLocation(){result = this.getVar().getDeclarationNode().getLocation()}

  AstNode getRHS(){result = this.getVar().getDeclarationNode()}

  StackVar getVar(){this = TSSAVar(result)}

  override
  int getOrd(){result = -1}
}

newtype TStackVar_type = TStackVar(int idx, AstNode n){
  idx in [1 .. n.getNumberOfOutputArgs()]
}


class StackVar extends TStackVar{
    StackVar(){ 
      // exists(AstNode n| this = n and varInternalIndex in [1 .. n.getNumberOfOutputArgs()]) }
      exists(AstNode n, int i| this = TStackVar(i, n)) }

    string getIdentifier(){result = "V" + this.getDeclarationNode().getLineNumber() + "_" + this.getInternalOutputIndex().toString()}
    
    string toString(){result = this.getIdentifier()}

    // SSAWriteDef toDef(){result = TStackVar(this.getInternalOutputIndex(), this)}
    SSAWriteDef toDef(){
      exists(SSAWriteDef def | def.getVar() = this and 
      def.getRHS() = this.getDeclarationNode() and result=def)
    }

    Location getLocation(){
      result = this.getDeclarationNode().getLocation()
    }

    AstNode getDeclarationNode(){this = TStackVar(_, result)}

    int getInternalOutputIndex(){this = TStackVar(result, _)}

    int getBBI(){this.getDeclarationNode().getBasicBlock().getNode(result).getAstNode() = this.getDeclarationNode()}

  /** Holds if `(this, v)` reaches the end of its origin basic block. */
  predicate reachesEndOfOriginBB() {
      not exists(this.getDeclarationNode().getConsumedBy(this))
  }

  int outStackOrder(){
    this = rank[result](StackVar v | this.getDeclarationNode().getBasicBlock().getANode().getAstNode().getAnOutputVar() = v and v.reachesEndOfOriginBB() | 
     v order by v.getDeclarationNode().getLineNumber() desc)
    //  v order by v.getDeclarationNode().getLineNumber())
  }

  BasicBlock getBasicBlock(){
    result = this.getDeclarationNode().getBasicBlock()
  }

  predicate reaches(AstNode n){
    this.getDeclarationNode().reaches(n)
  }

  int tryCastToInt(){
    this.inferType() = "uint64" and
    result = this.getDeclarationNode().(IntegerConstant).getValue() or
    result = this.getDeclarationNode().(LoadOpcode).getScratchSpaceStoredVariable().tryCastToInt()
    // or result = this.getDeclarationNode().(IntegerAddOpcode).
    //or
    //TODO: add all cases of operations that end up becoming integer constants
    //e.g. a btoi of a byte constant
    //TODO: we might now use infertype()
  }

  //TODO:
  //this is running out of mem. Instead of doing it like this, put type inference on each op separately
  cached
  string inferType(){
    if this.getDeclarationNode() instanceof TOpcode_btoi
    or this.getDeclarationNode() instanceof TOpcode_add
    or this.getDeclarationNode() instanceof TOpcode_pushint
    or this.getDeclarationNode() instanceof TOpcode_pushints
    or this.getDeclarationNode() instanceof TOpcode_intc
    or this.getDeclarationNode() instanceof TOpcode_intc_0
    or this.getDeclarationNode() instanceof TOpcode_intc_1
    or this.getDeclarationNode() instanceof TOpcode_intc_2
    or this.getDeclarationNode() instanceof TOpcode_intc_3
    or this.getDeclarationNode() instanceof TOpcode_div
    or this.getDeclarationNode() instanceof TOpcode_mul
    or this.getDeclarationNode() instanceof TOpcode_mod
    or this.getDeclarationNode() instanceof TOpcode_len
    or this.getDeclarationNode() instanceof TOpcode_shl
    or this.getDeclarationNode() instanceof TOpcode_shr
    or this.getDeclarationNode() instanceof TOpcode_sub
    or this.getDeclarationNode() instanceof TOpcode_not
    or this.getDeclarationNode() instanceof TOpcode_sqrt
    or this.getDeclarationNode() instanceof TOpcode_exp
    or this.getDeclarationNode() instanceof TOpcode_extract_uint16
    or this.getDeclarationNode() instanceof TOpcode_extract_uint32
    or this.getDeclarationNode() instanceof TOpcode_extract_uint64

    or this.getDeclarationNode() instanceof TOpcode_and
    or this.getDeclarationNode() instanceof TOpcode_or

    // the top output of this opcode is a boolean flag
    or this.getDeclarationNode() instanceof TOpcode_app_global_get_ex
    and this.getInternalOutputIndex() = 2

    // the top output of this opcode is a boolean flag
    or this.getDeclarationNode() instanceof TOpcode_app_local_get_ex
    and this.getInternalOutputIndex() = 2

    or this.getDeclarationNode() instanceof TxnOpcode and
      this.getDeclarationNode().(TxnOpcode).isIntegerField()

    or this.getDeclarationNode() instanceof GtxnOpcode and
      this.getDeclarationNode().(GtxnOpcode).isIntegerField()

    or this.getDeclarationNode() instanceof GtxnsOpcode and
      this.getDeclarationNode().(GtxnsOpcode).isIntegerField()

    or this.getDeclarationNode() instanceof TxnaOpcode and
      this.getDeclarationNode().(TxnaOpcode).isIntegerField()

    or this.getDeclarationNode() instanceof GlobalOpcode and
      this.getDeclarationNode().(GlobalOpcode).isIntegerField()
  
    or this.getDeclarationNode() instanceof TOpcode_gt
    or this.getDeclarationNode() instanceof TOpcode_gte
    or this.getDeclarationNode() instanceof TOpcode_lt
    or this.getDeclarationNode() instanceof TOpcode_lte
    or this.getDeclarationNode() instanceof TOpcode_neq
    or this.getDeclarationNode() instanceof TOpcode_eq
    or this.getDeclarationNode() instanceof TOpcode_app_opted_in
    or this.getDeclarationNode() instanceof TOpcode_ed25519verify_bare
    or this.getDeclarationNode() instanceof TOpcode_ec_pairing_check

    or this.getDeclarationNode() instanceof TOpcode_getbit

    or this.getDeclarationNode() instanceof TOpcode_bitlen
  
    or this.getDeclarationNode() instanceof TOpcode_min_balance
    or this.getDeclarationNode() instanceof TOpcode_online_stake
    or this.getDeclarationNode() instanceof TOpcode_addw
    or this.getDeclarationNode() instanceof TOpcode_mulw
    or this.getDeclarationNode() instanceof TOpcode_divmodw
    or this.getDeclarationNode() instanceof TOpcode_expw
  
    or this.getDeclarationNode() instanceof TOpcode_getbyte

    //pseudo opcodes
    or this.getDeclarationNode() instanceof TOpcode_int

    then
    result = "uint64"
    
    else if this.getDeclarationNode() instanceof LoadOpcode then
    result = this.getDeclarationNode().(LoadOpcode).getScratchSpaceStoredVariable().inferType()

    else if this.getDeclarationNode() instanceof TOpcode_pushbytes
    or this.getDeclarationNode() instanceof TOpcode_pushbytess
    or this.getDeclarationNode() instanceof TOpcode_itob
    or this.getDeclarationNode() instanceof TOpcode_bytec
    or this.getDeclarationNode() instanceof TOpcode_bytec_0
    or this.getDeclarationNode() instanceof TOpcode_bytec_1
    or this.getDeclarationNode() instanceof TOpcode_bytec_2
    or this.getDeclarationNode() instanceof TOpcode_bytec_3

    or this.getDeclarationNode() instanceof TOpcode_badd
    or this.getDeclarationNode() instanceof TOpcode_bmul
    or this.getDeclarationNode() instanceof TOpcode_bsub
    or this.getDeclarationNode() instanceof TOpcode_bdiv
    or this.getDeclarationNode() instanceof TOpcode_bmod

    or this.getDeclarationNode() instanceof TOpcode_concat
    or this.getDeclarationNode() instanceof TOpcode_keccak256
    or this.getDeclarationNode() instanceof TOpcode_ecdsa_pk_recover
    or this.getDeclarationNode() instanceof TOpcode_ecdsa_pk_decompress
    or this.getDeclarationNode() instanceof TOpcode_sha256
    or this.getDeclarationNode() instanceof TOpcode_sha3_256
    or this.getDeclarationNode() instanceof TOpcode_sha512_256

    or this.getDeclarationNode() instanceof TxnOpcode and
      this.getDeclarationNode().(TxnOpcode).isBytesField()

    or this.getDeclarationNode() instanceof TxnaOpcode and
      this.getDeclarationNode().(TxnaOpcode).isBytesField()

    or this.getDeclarationNode() instanceof GlobalOpcode and
      this.getDeclarationNode().(GlobalOpcode).isBytesField()

    // or this.getDeclarationNode() instanceof GtxnOpcode and
    //   this.getDeclarationNode().(GtxnOpcode).isBytesField()

    or this.getDeclarationNode() instanceof GtxnsOpcode and
      this.getDeclarationNode().(GtxnsOpcode).isBytesField()

    or this.getDeclarationNode() instanceof TOpcode_extract
    or this.getDeclarationNode() instanceof TOpcode_extract3
    or this.getDeclarationNode() instanceof TOpcode_box_extract
  
    or this.getDeclarationNode() instanceof TOpcode_replace2
    or this.getDeclarationNode() instanceof TOpcode_replace3
    or this.getDeclarationNode() instanceof TOpcode_substring
    or this.getDeclarationNode() instanceof TOpcode_substring3

    or this.getDeclarationNode() instanceof TOpcode_bzero

    then
    result = "bytes"

    //Stack reorganization opcodes need to apply  type inference according to
    // their "passthrough" schema
    else if this.getDeclarationNode() instanceof TOpcode_dup
      then result = getGenerator(this.getDeclarationNode().getStackInputByOrder(1)).inferType()
    
    else if this.getDeclarationNode() instanceof TOpcode_swap
      and this.getInternalOutputIndex() = 1
      then result = getGenerator(this.getDeclarationNode().getStackInputByOrder(1)).inferType()

    else if this.getDeclarationNode() instanceof TOpcode_swap
      and this.getInternalOutputIndex() = 2
      then result = getGenerator(this.getDeclarationNode().getStackInputByOrder(2)).inferType()
    
    // //In a cover, if this is the first output, give me the type of the first input:
    // // s_n      <---- n in input order
    // // s_n-1    <---- n-1 in input order
    // // ...
    // // s_2      <---- 2 in input order
    // // s_1      <---- 1 in input order 
    // // cover n
    // // s_1      <---- 1 in output order
    // // s_n      <---- 2 in output order
    // // s_n-1    <---- 3 in output order
    // // ...
    // // s_2      <---- n in output order
    // else if this.getDeclarationNode() instanceof TOpcode_cover
    //   and this.getInternalOutputIndex() = 1
    //   then result = getGenerator(this.getDeclarationNode().getStackInputByOrder(1)).inferType()
    // else if this.getDeclarationNode() instanceof TOpcode_cover
    //   and this.getInternalOutputIndex() != 1
    //   and this.getInternalOutputIndex() in [2 .. this.getDeclarationNode().getNumberOfOutputArgs()]
    //   then result = getGenerator(this.getDeclarationNode().getStackInputByOrder(
    //     this.getDeclarationNode().getNumberOfConsumedArgs() + 2 - this.getInternalOutputIndex()
    //   )).inferType()

    // uncover is the reverse of cover
    // s_n      <---- n in input order
    // s_n-1    <---- n-1 in input order
    // ...
    // s_2      <---- 2 in input order
    // s_1      <---- 1 in input order
    // uncover n
    // s_n-1    <---- 1 in output order
    // ...
    // s_2      <---- n-2 in output order
    // s_1      <---- n-1 in output order
    // s_n      <---- n in output order
    else if this.getDeclarationNode() instanceof TOpcode_uncover then(
      this.getInternalOutputIndex() = this.getDeclarationNode().getNumberOfOutputArgs()
      and result = getGenerator(this.getDeclarationNode().getStackInputByOrder(
        this.getDeclarationNode().getNumberOfConsumedArgs()
      )).inferType()
      or
      this.getInternalOutputIndex() != this.getDeclarationNode().getNumberOfOutputArgs()
      // and this.getInternalOutputIndex() in [1 .. this.getDeclarationNode().getNumberOfOutputArgs()-1]
      and result = getGenerator(this.getDeclarationNode().getStackInputByOrder(
        this.getDeclarationNode().getNumberOfConsumedArgs() - this.getInternalOutputIndex()
      )).inferType()
    )
    
    // dig is the reverse of cover
    // s_n+1    <---- n+1 in input order
    // s_n      <---- n in input order
    // s_n-1    <---- n-1 in input order
    // ...
    // s_2      <---- 2 in input order
    // s_1      <---- 1 in input order
    // dig n
    // s_n+1    <---- 1 in output order
    // ...
    // s_2      <---- n-1 in output order
    // s_1      <---- n in output order
    // s_n+1    <---- n+1 in output order
    else if this.getDeclarationNode() instanceof TOpcode_dig then(
      (this.getInternalOutputIndex() = 1 or this.getInternalOutputIndex() = this.getDeclarationNode().getNumberOfOutputArgs())
      and result = getGenerator(this.getDeclarationNode().getStackInputByOrder(
        this.getDeclarationNode().getNumberOfConsumedArgs()
      )).inferType()
      or
    // this.getInternalOutputIndex() in [2 .. this.getDeclarationNode().getNumberOfOutputArgs() - 1]
      this.getInternalOutputIndex() != 1 and this.getInternalOutputIndex() != this.getDeclarationNode().getNumberOfOutputArgs()
      and result = getGenerator(this.getDeclarationNode().getStackInputByOrder(
        this.getInternalOutputIndex()-1
      )).inferType()
    )

    else result = "Undefined"
  }
}

// newtype TBool = Bool(int n){n = 0 or n = 1}
// class AVMBool extends TBool{
//   private int value;

//   AVMBool(){(value = 0 or value = 1) and this = Bool(value)}

//   string toString(){if value = 0 then result = "true" else result = "false"}
// }

// newtype UInt64 = TUInt64();

// class AVMType extends TUint64

// newtype AVMType = TBytes(int len){len in [0 .. 4096]} or TUint64(QlBuiltins::BigInt b){b in [0 .. QlBuiltins::BigInt(18446744073709551615)]};


class DirectPhi extends Definition instanceof TDirectPhi{
  int initialStackIndex;
  BasicBlock bb;

  DirectPhi(){
    exists(StackVar v | v.reachesEndOfOriginBB()
      and bb = v.getBasicBlock().getASuccessor() 
      and v.reaches(bb.getFirstNode().getAstNode())
      and
      initialStackIndex = v.outStackOrder() and
      this = TDirectPhi(initialStackIndex, bb)
      )
  }

  int getInitialStackIndex(){result = initialStackIndex}

  override
  int getOrd(){result = this.getInitialStackIndex()}

  BasicBlock getBasicBlock(){result = bb}

  // IndirectPhi getInput(){
  //   result.getBasicBlock() = bb.getAPredecessor() and
  //   this = phiNodeExitIndex(result, result.getBasicBlock())
  // }

  StackVar getOriginatingInput(){
    result.getBasicBlock() = bb.getAPredecessor() and
    this.getInitialStackIndex() = result.outStackOrder()
  }

  override Location getLocation(){result = bb.getFirstNode().getLocation()}

  override string toString(){
    result = "(d)phi_" + bb.getFirstNode() + "_" + this.getInitialStackIndex()
  }

  AstNode getConsumedBy(){
    result = phiNodeGetsConsumedBy(initialStackIndex, bb)
  }

  // override Location getLocation(){result = this.getBasicBlock().getLocation()}
}

// DirectPhi getStackInput_DP(int stackOrder, BasicBlock bb){
//   result.getBasicBlock().getASuccessor() = bb and
//   stackOrder = phiNodeExitIndex(result.getInitialStackIndex(), result.getBasicBlock())
// }

// IndirectPhi getStackInput_IP(int stackOrder, BasicBlock bb){
//   result.getBasicBlock().getASuccessor() = bb and
//   stackOrder = phiNodeExitIndex(result, result.getBasicBlock())
// }

// StackVar getStackInput_Var(int stackOrder, BasicBlock bb){
//   result.getBasicBlock().getASuccessor() = bb and
//   stackOrder = result.outStackOrder()
// }

StackVar getGenerator(Definition def){
  def instanceof DirectPhi and result = def.(DirectPhi).getOriginatingInput()
  or def instanceof IndirectPhi and result = getGenerator(def.(IndirectPhi).getGenerator()) 
  or def instanceof SSAWriteDef and result.toDef() = def
}


class IndirectPhi extends Definition instanceof TIndirectPhi{
  int initialStackIndex;
  BasicBlock bb;

  IndirectPhi(){
    exists(DirectPhi phi | initialStackIndex = phiNodeExitIndex(phi.getInitialStackIndex(), phi.getBasicBlock())
      and bb = phi.getBasicBlock().getASuccessor()

      //testing
      and any(phi.getOriginatingInput()).reaches(bb.getFirstNode().getAstNode())

      and this = TIndirectPhi(initialStackIndex, bb)
      // and this = "IPhi_" + bb.getFirstNode().getAstNode() + "_" + initialStackIndex.toString() + "D"
      // and generator = phi
      ) 
      or 
      // not exists(DirectPhi phi | initialStackIndex = phiNodeExitIndex(phi.getInitialStackIndex(), phi.getBasicBlock())
      // and bb = phi.getBasicBlock().getASuccessor()) and
    exists(IndirectPhi phi | phi.getBasicBlock().getASuccessor() = bb and 
        initialStackIndex = phiNodeExitIndex(phi.getInitialStackIndex(), phi.getBasicBlock())
        
        //testing
        and exists(DirectPhi d_phi | d_phi = phi.getGenerator() and d_phi.getOriginatingInput().reaches(bb.getFirstNode().getAstNode())) 
        // and exists(phi.getGenerator()) 

        and this = TIndirectPhi(initialStackIndex, bb)
    )
  }

  BasicBlock getBasicBlock(){result = bb}

  int getInitialStackIndex(){result = initialStackIndex}

  DirectPhi getGenerator(){
    exists(DirectPhi phi | this.getInitialStackIndex() = phiNodeExitIndex(phi.getInitialStackIndex(), phi.getBasicBlock())
      and bb = phi.getBasicBlock().getASuccessor() and result = phi) or
    exists(IndirectPhi phi | phi.getBasicBlock().getASuccessor() = bb and 
      this.getInitialStackIndex() = phiNodeExitIndex(phi.getInitialStackIndex(), phi.getBasicBlock()) 
      and result = phi.getGenerator())
  }

  override string toString(){
    result = "phi_" + bb.getFirstNode() + "_" + this.getInitialStackIndex()
  }

  AstNode getConsumedBy(){
    result = phiNodeGetsConsumedBy(initialStackIndex, bb)
  }

  override Location getLocation(){result = this.getBasicBlock().getLocation()}

  override int getOrd(){result = this.getInitialStackIndex()}
}


// cached
// int basicBlockStackHeightDelta(BasicBlock b){
//   result = 
//   sum(int i | i in [0 .. b.length()-1] | b.getNode(i).getAstNode().getNumberOfOutputArgs() -
//   b.getNode(i).getAstNode().getNumberOfConsumedArgs())
// }

// int bbStackHeightPair(BasicBlock a, BasicBlock b){
//   a = b.getAPredecessor() and
//   result = basicBlockStackHeightDelta(a) + basicBlockStackHeightDelta(b)
// }




// This function does the following calculation:
// given a hypothetical phi node at the start of a basic block,
// it tells me which nodes would be consumed and if so by which opcodes
cached
AstNode phiNodeGetsConsumedBy(int hypotheticalPhiIndex, BasicBlock b){
  hypotheticalPhiIndex in [1 .. 100] and //should be 1000 for max stack, but we use 100 for perf. reasons
    result = rank[1](AstNode end|
        end = b.getANode().getAstNode() and
        hypotheticalPhiIndex + getPartialStackSizeBeforeOutput(end.getBasicBlock().getFirstNode().getAstNode(), end) <= 0
        | end order by end.getLineNumber()
    )
}

cached
int phiNodeExitIndex(int hypotheticalPhiNodeExitIndex, BasicBlock b){
  hypotheticalPhiNodeExitIndex in [1 .. 1000] and
  not exists(phiNodeGetsConsumedBy(hypotheticalPhiNodeExitIndex, b)) and
  result = max(StackVar v | v.getBasicBlock() = b | v.outStackOrder()) +
  hypotheticalPhiNodeExitIndex - count(int h | exists(phiNodeGetsConsumedBy(h, b)) and 
    h in [1 .. hypotheticalPhiNodeExitIndex])
}

// cached
// AstNode writeDefGetsConsumedBy(int writeDefInternalIndex, AstNode defNode, BasicBlock b){
//   writeDefInternalIndex in [1 .. defNode.getNumberOfOutputArgs()] and
//     result = rank[1](AstNode end|
//         end = b.getANode().getAstNode() and end.getLineNumber() > defNode.getLineNumber() and
//         writeDefInternalIndex + getPartialStackSizeBeforeOutput(defNode.getNextLine(), end) <= 0
//         | end order by end.getLineNumber()
//     )
// }