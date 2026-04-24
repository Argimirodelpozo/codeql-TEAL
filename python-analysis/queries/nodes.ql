/**
 * @name Graph Nodes
 * @description One row per AST node referenced by the CFG or dataflow graphs (opcodes plus any
 *              other AST nodes that appear as edge endpoints). The emitted class name is the
 *              *most specific* opcode class the node belongs to — many leaf opcode classes
 *              (`IntegerAddOpcode`, `SubOpcode`, ...) do not override `getAPrimaryQlClass()`,
 *              so we dispatch manually on `instanceof` to give consumers leaf-level types.
 * @id tealql/python-analysis/nodes
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow
import codeql.teal.cfg.CFG
import codeql.teal.cfg.CFG::CfgImpl

/**
 * Gets the name of the most specific opcode class that `n` belongs to,
 * when `n` matches one of the enumerated leaf opcode classes.
 */
string specificOpcodeClass(AstNode n) {
  // Arithmetic
  n instanceof IntegerAddOpcode and result = "IntegerAddOpcode"
  or n instanceof SubOpcode and result = "SubOpcode"
  or n instanceof MulOpcode and result = "MulOpcode"
  or n instanceof DivOpcode and result = "DivOpcode"
  or n instanceof ModOpcode and result = "ModOpcode"
  or n instanceof AddwOpcode and result = "AddwOpcode"
  or n instanceof MulwOpcode and result = "MulwOpcode"
  or n instanceof DivmodwOpcode and result = "DivmodwOpcode"
  or n instanceof ExpOpcode and result = "ExpOpcode"
  or n instanceof ExpwOpcode and result = "ExpwOpcode"
  or n instanceof DivwOpcode and result = "DivwOpcode"
  or n instanceof SqrtOpcode and result = "SqrtOpcode"
  or n instanceof ShlOpcode and result = "ShlOpcode"
  or n instanceof ShrOpcode and result = "ShrOpcode"
  // Byte arithmetic
  or n instanceof BaddOpcode and result = "BaddOpcode"
  or n instanceof BsubOpcode and result = "BsubOpcode"
  or n instanceof BdivOpcode and result = "BdivOpcode"
  or n instanceof BmulOpcode and result = "BmulOpcode"
  or n instanceof BmodOpcode and result = "BmodOpcode"
  or n instanceof BsqrtOpcode and result = "BsqrtOpcode"
  // Integer comparison + logical not
  or n instanceof EqualsComparisonOpcode and result = "EqualsComparisonOpcode"
  or n instanceof NotEqualsComparisonOpcode and result = "NotEqualsComparisonOpcode"
  or n instanceof NotOpcode and result = "NotOpcode"
  or n instanceof IntegerLessThanOpcode and result = "IntegerLessThanOpcode"
  or n instanceof IntegerLteOpcode and result = "IntegerLteOpcode"
  or n instanceof IntegerGreaterThanOpcode and result = "IntegerGreaterThanOpcode"
  or n instanceof IntegerGteOpcode and result = "IntegerGteOpcode"
  or n instanceof IntegerEqualsOpcode and result = "IntegerEqualsOpcode"
  or n instanceof IntegerNotEqualsOpcode and result = "IntegerNotEqualsOpcode"
  // Byte comparison
  or n instanceof BltOpcode and result = "BltOpcode"
  or n instanceof BgtOpcode and result = "BgtOpcode"
  or n instanceof BlteOpcode and result = "BlteOpcode"
  or n instanceof BgteOpcode and result = "BgteOpcode"
  or n instanceof BeqOpcode and result = "BeqOpcode"
  or n instanceof BneqOpcode and result = "BneqOpcode"
  // Logic (integer + byte bitwise)
  or n instanceof AndOpcode and result = "AndOpcode"
  or n instanceof OrOpcode and result = "OrOpcode"
  or n instanceof BitandOpcode and result = "BitandOpcode"
  or n instanceof BitorOpcode and result = "BitorOpcode"
  or n instanceof BitxorOpcode and result = "BitxorOpcode"
  or n instanceof BitnotOpcode and result = "BitnotOpcode"
  or n instanceof BorOpcode and result = "BorOpcode"
  or n instanceof BandOpcode and result = "BandOpcode"
  or n instanceof BxorOpcode and result = "BxorOpcode"
  or n instanceof BnotOpcode and result = "BnotOpcode"
  // Byte-string operations
  or n instanceof ConcatOpcode and result = "ConcatOpcode"
  or n instanceof SubstringOpcode and result = "SubstringOpcode"
  or n instanceof Substring3Opcode and result = "Substring3Opcode"
  or n instanceof ExtractOpcode and result = "ExtractOpcode"
  or n instanceof Extract3Opcode and result = "Extract3Opcode"
  or n instanceof ExtractUint16Opcode and result = "ExtractUint16Opcode"
  or n instanceof ExtractUint32Opcode and result = "ExtractUint32Opcode"
  or n instanceof ExtractUint64Opcode and result = "ExtractUint64Opcode"
  or n instanceof Replace2Opcode and result = "Replace2Opcode"
  or n instanceof Replace3Opcode and result = "Replace3Opcode"
  or n instanceof LenOpcode and result = "LenOpcode"
  or n instanceof BitlenOpcode and result = "BitlenOpcode"
  or n instanceof GetbitOpcode and result = "GetbitOpcode"
  or n instanceof SetbitOpcode and result = "SetbitOpcode"
  or n instanceof GetbyteOpcode and result = "GetbyteOpcode"
  or n instanceof SetbyteOpcode and result = "SetbyteOpcode"
  or n instanceof ItobOpcode and result = "ItobOpcode"
  or n instanceof BtoiOpcode and result = "BtoiOpcode"
  or n instanceof Base64DecodeOpcode and result = "Base64DecodeOpcode"
  or n instanceof JsonRefOpcode and result = "JsonRefOpcode"
  // Constants / pushes / block loads
  or n instanceof IntOpcode and result = "IntOpcode"
  or n instanceof IntcblockOpcode and result = "IntcblockOpcode"
  or n instanceof IntcOpcode and result = "IntcOpcode"
  or n instanceof Intc0Opcode and result = "Intc0Opcode"
  or n instanceof Intc1Opcode and result = "Intc1Opcode"
  or n instanceof Intc2Opcode and result = "Intc2Opcode"
  or n instanceof Intc3Opcode and result = "Intc3Opcode"
  or n instanceof PushintOpcode and result = "PushintOpcode"
  or n instanceof PushintsOpcode and result = "PushintsOpcode"
  or n instanceof BytecblockOpcode and result = "BytecblockOpcode"
  or n instanceof BytecOpcode and result = "BytecOpcode"
  or n instanceof Bytec0Opcode and result = "Bytec0Opcode"
  or n instanceof Bytec1Opcode and result = "Bytec1Opcode"
  or n instanceof Bytec2Opcode and result = "Bytec2Opcode"
  or n instanceof Bytec3Opcode and result = "Bytec3Opcode"
  or n instanceof PushbytesOpcode and result = "PushbytesOpcode"
  or n instanceof PushbytessOpcode and result = "PushbytessOpcode"
  or n instanceof BzeroOpcode and result = "BzeroOpcode"
  // Control flow
  or n instanceof ReturnOpcode and result = "ReturnOpcode"
  or n instanceof ErrOpcode and result = "ErrOpcode"
  or n instanceof AssertOpcode and result = "AssertOpcode"
  or n instanceof BOpcode and result = "BOpcode"
  or n instanceof CallsubOpcode and result = "CallsubOpcode"
  or n instanceof RetsubOpcode and result = "RetsubOpcode"
  or n instanceof BnzOpcode and result = "BnzOpcode"
  or n instanceof BzOpcode and result = "BzOpcode"
  or n instanceof SwitchOpcode and result = "SwitchOpcode"
  or n instanceof MatchOpcode and result = "MatchOpcode"
  // Crypto
  or n instanceof Ed25519verifyOpcode and result = "Ed25519verifyOpcode"
  or n instanceof Ed25519verifyBareOpcode and result = "Ed25519verifyBareOpcode"
  or n instanceof EcdsaVerifyOpcode and result = "EcdsaVerifyOpcode"
  or n instanceof EcdsaPkDecompressOpcode and result = "EcdsaPkDecompressOpcode"
  or n instanceof EcdsaPkRecoverOpcode and result = "EcdsaPkRecoverOpcode"
  or n instanceof VrfVerifyOpcode and result = "VrfVerifyOpcode"
  // Elliptic curve
  or n instanceof EcAddOpcode and result = "EcAddOpcode"
  or n instanceof EcMulOpcode and result = "EcMulOpcode"
  or n instanceof EcPairingCheckOpcode and result = "EcPairingCheckOpcode"
  or n instanceof EcMultiScalarMulOpcode and result = "EcMultiScalarMulOpcode"
  or n instanceof EcSubgroupCheckOpcode and result = "EcSubgroupCheckOpcode"
  or n instanceof EcMapToOpcode and result = "EcMapToOpcode"
  // Hashing
  or n instanceof Sha256Opcode and result = "Sha256Opcode"
  or n instanceof Sha512_256Opcode and result = "Sha512_256Opcode"
  or n instanceof Keccak256Opcode and result = "Keccak256Opcode"
  or n instanceof Sha3_256Opcode and result = "Sha3_256Opcode"
  or n instanceof MimcOpcode and result = "MimcOpcode"
  // Global / app / asset / account state
  or n instanceof GlobalOpcode and result = "GlobalOpcode"
  or n instanceof AppOptedInOpcode and result = "AppOptedInOpcode"
  or n instanceof AppLocalGetOpcode and result = "AppLocalGetOpcode"
  or n instanceof AppLocalGetExOpcode and result = "AppLocalGetExOpcode"
  or n instanceof AppGlobalGetOpcode and result = "AppGlobalGetOpcode"
  or n instanceof AppGlobalGetExOpcode and result = "AppGlobalGetExOpcode"
  or n instanceof AppLocalPutOpcode and result = "AppLocalPutOpcode"
  or n instanceof AppGlobalPutOpcode and result = "AppGlobalPutOpcode"
  or n instanceof AppLocalDelOpcode and result = "AppLocalDelOpcode"
  or n instanceof AppGlobalDelOpcode and result = "AppGlobalDelOpcode"
  or n instanceof AppParamsGetOpcode and result = "AppParamsGetOpcode"
  or n instanceof AssetHoldingGetOpcode and result = "AssetHoldingGetOpcode"
  or n instanceof AssetParamsGetOpcode and result = "AssetParamsGetOpcode"
  or n instanceof AcctParamsGetOpcode and result = "AcctParamsGetOpcode"
  or n instanceof BalanceOpcode and result = "BalanceOpcode"
  or n instanceof MinBalanceOpcode and result = "MinBalanceOpcode"
  or n instanceof OnlineStakeOpcode and result = "OnlineStakeOpcode"
  or n instanceof VoterParamsGetOpcode and result = "VoterParamsGetOpcode"
  // Box storage
  or n instanceof BoxCreateOpcode and result = "BoxCreateOpcode"
  or n instanceof BoxExtractOpcode and result = "BoxExtractOpcode"
  or n instanceof BoxReplaceOpcode and result = "BoxReplaceOpcode"
  or n instanceof BoxDelOpcode and result = "BoxDelOpcode"
  or n instanceof BoxLenOpcode and result = "BoxLenOpcode"
  or n instanceof BoxGetOpcode and result = "BoxGetOpcode"
  or n instanceof BoxPutOpcode and result = "BoxPutOpcode"
  or n instanceof BoxSpliceOpcode and result = "BoxSpliceOpcode"
  or n instanceof BoxResizeOpcode and result = "BoxResizeOpcode"
  // Transaction accessors
  or n instanceof TxnOpcode and result = "TxnOpcode"
  or n instanceof TxnaOpcode and result = "TxnaOpcode"
  or n instanceof TxnasOpcode and result = "TxnasOpcode"
  or n instanceof GtxnOpcode and result = "GtxnOpcode"
  or n instanceof GtxnaOpcode and result = "GtxnaOpcode"
  or n instanceof GtxnasOpcode and result = "GtxnasOpcode"
  or n instanceof GtxnsOpcode and result = "GtxnsOpcode"
  or n instanceof GtxnsaOpcode and result = "GtxnsaOpcode"
  or n instanceof GtxnsasOpcode and result = "GtxnsasOpcode"
  or n instanceof GitxnOpcode and result = "GitxnOpcode"
  or n instanceof GitxnaOpcode and result = "GitxnaOpcode"
  or n instanceof GitxnasOpcode and result = "GitxnasOpcode"
  // Inner transactions
  or n instanceof ItxnOpcode and result = "ItxnOpcode"
  or n instanceof ItxnaOpcode and result = "ItxnaOpcode"
  or n instanceof ItxnasOpcode and result = "ItxnasOpcode"
  or n instanceof InnerTransactionField and result = "InnerTransactionField"
  or n instanceof InnerTransactionBegin and result = "InnerTransactionBegin"
  or n instanceof InnerTransactionNext and result = "InnerTransactionNext"
  or n instanceof InnerTransactionSubmit and result = "InnerTransactionSubmit"
  // Logging
  or n instanceof LogOpcode and result = "LogOpcode"
  // Scratch space
  or n instanceof LoadOpcode and result = "LoadOpcode"
  or n instanceof StoreOpcode and result = "StoreOpcode"
  or n instanceof LoadsOpcode and result = "LoadsOpcode"
  or n instanceof StoresOpcode and result = "StoresOpcode"
  or n instanceof GloadOpcode and result = "GloadOpcode"
  or n instanceof GloadsOpcode and result = "GloadsOpcode"
  or n instanceof GloadssOpcode and result = "GloadssOpcode"
  or n instanceof GaidOpcode and result = "GaidOpcode"
  or n instanceof GaidsOpcode and result = "GaidsOpcode"
  // Stack manipulation
  or n instanceof DigOpcode and result = "DigOpcode"
  or n instanceof ProtoOpcode and result = "ProtoOpcode"
  or n instanceof PopOpcode and result = "PopOpcode"
  or n instanceof PopnOpcode and result = "PopnOpcode"
  or n instanceof DupOpcode and result = "DupOpcode"
  or n instanceof Dup2Opcode and result = "Dup2Opcode"
  or n instanceof DupnOpcode and result = "DupnOpcode"
  or n instanceof SwapOpcode and result = "SwapOpcode"
  or n instanceof BuryOpcode and result = "BuryOpcode"
  or n instanceof CoverOpcode and result = "CoverOpcode"
  or n instanceof UncoverOpcode and result = "UncoverOpcode"
  or n instanceof FrameDigOpcode and result = "FrameDigOpcode"
  or n instanceof FrameBuryOpcode and result = "FrameBuryOpcode"
  or n instanceof SelectOpcode and result = "SelectOpcode"
  // Misc
  or n instanceof ArgOpcode and result = "ArgOpcode"
  or n instanceof Arg0Opcode and result = "Arg0Opcode"
  or n instanceof Arg1Opcode and result = "Arg1Opcode"
  or n instanceof Arg2Opcode and result = "Arg2Opcode"
  or n instanceof Arg3Opcode and result = "Arg3Opcode"
  or n instanceof ArgsOpcode and result = "ArgsOpcode"
  or n instanceof BlockOpcode and result = "BlockOpcode"
}

/** The class name to emit for `n` — leaf opcode class if available, else `getAPrimaryQlClass()`. */
string nodeClass(AstNode n) {
  result = specificOpcodeClass(n)
  or
  not exists(specificOpcodeClass(n)) and result = n.getAPrimaryQlClass()
}

from AstNode n
where
  n instanceof Opcode
  or
  exists(Dataflow::Node nd | nd.getUnderlyingASTNode() = n)
  or
  exists(AstCfgNode cn | cn.getAstNode() = n)
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       n.getLocation().getStartColumn(),
       n.getLocation().getEndLine(),
       n.getLocation().getEndColumn(),
       nodeClass(n)
