"""TEAL AST node types — the objects :mod:`tealql.tealtools.frontend.graph` stores as graph nodes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional


# ----- Location -------------------------------------------------------------

@dataclass(frozen=True)
class Location:
    """A source range: 1-based lines, 0-based half-open columns ``[start, end)``."""
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __str__(self) -> str:
        return f"{self.file}:{self.start_line}:{self.start_column}"


# ----- Base class + registry ------------------------------------------------

class AstNode:
    """Any TEAL AST node that can appear as a graph node.

    HAZARD: hashing/equality are keyed by ``(file, start_line)``, NOT by the
    instruction. One-instruction-per-line is architectural, shared with SSAVar
    identity ``(file, line, index)``, the scratch/cost/graph indexes and every
    reported violation — widening the key here means widening all of them.
    TEAL's grammar does permit ``int 1; int 2``, so
    :func:`tealql.tealtools.ast.parse.parse_nodes` records any such line as a
    ``ParseDiagnostic`` rather than letting it collapse into one node unnoticed.
    """

    #: ``node_class`` name -> concrete ``AstNode`` subclass.
    _registry: ClassVar[dict[str, type["AstNode"]]] = {}

    #: Opcode mnemonic -> the subclass that parses it (``"+"`` ->
    #: ``IntegerAddOpcode``). Built from each class's :attr:`mnemonic`, so the
    #: classes are the single source of truth (no separate string table).
    _by_mnemonic: ClassVar[dict[str, type["AstNode"]]] = {}

    #: Node-type identifier used throughout the graph; defaults to the class name.
    node_class: ClassVar[str] = "AstNode"

    #: Mnemonic this class parses; ``None`` for non-opcode / family classes.
    mnemonic: ClassVar[Optional[str]] = None

    #: Whether this node's identity is its SOURCE LOCATION (``(file, line)``) —
    #: true for every node that IS a line. A node spanning many lines (only
    #: :class:`Source`) sets this False and is identified by object instead:
    #: spanning from line 1, it otherwise compared equal to whatever sat on
    #: line 1 and displaced it from the graph. Both dunders below honour this,
    #: so hash and equality cannot disagree.
    location_identity: ClassVar[bool] = True

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "node_class" not in cls.__dict__:
            cls.node_class = cls.__name__
        AstNode._registry.setdefault(cls.node_class, cls)
        if "mnemonic" in cls.__dict__ and cls.mnemonic is not None:
            AstNode._by_mnemonic.setdefault(cls.mnemonic, cls)

    def __init__(self, location: Location, code: str):
        self.location = location
        self.code = code

    def __hash__(self) -> int:
        if not self.location_identity:
            return object.__hash__(self)
        return hash((self.location.file, self.location.start_line))

    def __eq__(self, other) -> bool:
        if not isinstance(other, AstNode):
            return NotImplemented
        # Either side opting out of location identity makes this an OBJECT
        # comparison — checked on BOTH sides, or the reflected ``__eq__`` would
        # still call two nodes on line 1 equal while their hashes differ.
        if not (self.location_identity and other.location_identity):
            return self is other
        return (
            self.location.file == other.location.file
            and self.location.start_line == other.location.start_line
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.location.file}:{self.location.start_line})"


def node_class_for_mnemonic(mnemonic: str) -> Optional[type["AstNode"]]:
    """The class that parses ``mnemonic`` (``"+"`` -> ``IntegerAddOpcode``), or ``None``."""
    return AstNode._by_mnemonic.get(mnemonic)


# ----- Top-level groupings --------------------------------------------------
# Every `Family...Opcode` base below is a pure Python grouping, never
# instantiated: it exists so `isinstance(n, ArithmeticOpcode)` selects a family.

class Opcode(AstNode):
    """Base class for every TEAL opcode."""


class NonOpcodeNode(AstNode):
    """Base for AST nodes that aren't opcodes (labels, comments, pragmas, ...)."""


# ----- Non-opcode node kinds ------------------------------------------------

class Label(NonOpcodeNode): pass
class LabelIdentifier(NonOpcodeNode): pass
class Comment(NonOpcodeNode): pass
class Token(NonOpcodeNode): pass
class ReservedWord(NonOpcodeNode): pass
class Source(NonOpcodeNode):
    """The whole-file container node — the one node that is not a line.

    HAZARD: it spans the file FROM LINE 1, so under the ``(file, line)``
    identity every other node uses it compared EQUAL to an instruction on line
    1 — and the graph's ``add_node`` keeps whichever arrives first (this one),
    silently deleting that instruction from the graph, from the SSA, and from
    every analysis downstream, with no diagnostic. Hence
    :attr:`AstNode.location_identity` is False here."""

    location_identity = False

class PragmaVersion(NonOpcodeNode): pass
class PragmaTypetrack(NonOpcodeNode): pass

class NumericArgument(NonOpcodeNode): pass
class HexbytesArgument(NonOpcodeNode): pass
class StringArgument(NonOpcodeNode): pass

class ItxnFieldName(NonOpcodeNode): pass


# ----- Argument-shape categories --------------------------------------------
# The node_class an opcode reports when no more specific leaf class claims it.

class ZeroArgumentOpcode(Opcode): pass
class SingleNumericArgumentOpcode(Opcode): pass
class DoubleNumericArgumentOpcode(Opcode): pass


# ----- Family: Arithmetic ---------------------------------------------------

class ArithmeticOpcode(Opcode): pass

class IntegerAddOpcode(ArithmeticOpcode): mnemonic = "+"
class SubOpcode(ArithmeticOpcode): mnemonic = "-"
class MulOpcode(ArithmeticOpcode): mnemonic = "*"
class DivOpcode(ArithmeticOpcode): mnemonic = "/"
class ModOpcode(ArithmeticOpcode): mnemonic = "%"
class AddwOpcode(ArithmeticOpcode): mnemonic = "addw"
class MulwOpcode(ArithmeticOpcode): mnemonic = "mulw"
class DivmodwOpcode(ArithmeticOpcode): mnemonic = "divmodw"
class ExpOpcode(ArithmeticOpcode): mnemonic = "exp"
class ExpwOpcode(ArithmeticOpcode): mnemonic = "expw"
class DivwOpcode(ArithmeticOpcode): mnemonic = "divw"
class SqrtOpcode(ArithmeticOpcode): mnemonic = "sqrt"
class ShlOpcode(ArithmeticOpcode): mnemonic = "shl"
class ShrOpcode(ArithmeticOpcode): mnemonic = "shr"


# ----- Family: Byte arithmetic ----------------------------------------------

class ByteArithmeticOpcode(Opcode): pass

class BaddOpcode(ByteArithmeticOpcode): mnemonic = "b+"
class BsubOpcode(ByteArithmeticOpcode): mnemonic = "b-"
class BdivOpcode(ByteArithmeticOpcode): mnemonic = "b/"
class BmulOpcode(ByteArithmeticOpcode): mnemonic = "b*"
class BmodOpcode(ByteArithmeticOpcode): mnemonic = "b%"
class BsqrtOpcode(ByteArithmeticOpcode): mnemonic = "bsqrt"


# ----- Family: Integer comparison + logical not -----------------------------

class ComparisonOpcode(Opcode): pass
class LogicalComparisonOp(ComparisonOpcode): pass

class EqualsComparisonOpcode(LogicalComparisonOp): mnemonic = "=="
class NotOpcode(ComparisonOpcode): mnemonic = "!"
class IntegerLessThanOpcode(ComparisonOpcode): mnemonic = "<"
class IntegerLteOpcode(ComparisonOpcode): mnemonic = "<="
class IntegerGreaterThanOpcode(ComparisonOpcode): mnemonic = ">"
class IntegerGteOpcode(ComparisonOpcode): mnemonic = ">="
class IntegerNotEqualsOpcode(ComparisonOpcode): mnemonic = "!="


# ----- Family: Byte comparison ----------------------------------------------

class ByteComparisonOpcode(Opcode): pass

class BltOpcode(ByteComparisonOpcode): mnemonic = "b<"
class BgtOpcode(ByteComparisonOpcode): mnemonic = "b>"
class BlteOpcode(ByteComparisonOpcode): mnemonic = "b<="
class BgteOpcode(ByteComparisonOpcode): mnemonic = "b>="
class BeqOpcode(ByteComparisonOpcode): mnemonic = "b=="
class BneqOpcode(ByteComparisonOpcode): mnemonic = "b!="


# ----- Family: Logic (integer + byte bitwise) -------------------------------

class LogicOpcode(Opcode): pass

class AndOpcode(LogicOpcode): mnemonic = "&&"
class OrOpcode(LogicOpcode): mnemonic = "||"
class BitandOpcode(LogicOpcode): mnemonic = "&"
class BitorOpcode(LogicOpcode): mnemonic = "|"
class BitxorOpcode(LogicOpcode): mnemonic = "^"
class BitnotOpcode(LogicOpcode): mnemonic = "~"
class BorOpcode(LogicOpcode): mnemonic = "b|"
class BandOpcode(LogicOpcode): mnemonic = "b&"
class BxorOpcode(LogicOpcode): mnemonic = "b^"
class BnotOpcode(LogicOpcode): mnemonic = "b~"


# ----- Family: Byte-string operations ---------------------------------------

class ByteOpsOpcode(Opcode): pass

class ConcatOpcode(ByteOpsOpcode): mnemonic = "concat"
class SubstringOpcode(ByteOpsOpcode): mnemonic = "substring"
class Substring3Opcode(ByteOpsOpcode): mnemonic = "substring3"
class ExtractOpcode(ByteOpsOpcode): mnemonic = "extract"
class Extract3Opcode(ByteOpsOpcode): mnemonic = "extract3"
class ExtractUint16Opcode(ByteOpsOpcode): mnemonic = "extract_uint16"
class ExtractUint32Opcode(ByteOpsOpcode): mnemonic = "extract_uint32"
class ExtractUint64Opcode(ByteOpsOpcode): mnemonic = "extract_uint64"
class Replace2Opcode(ByteOpsOpcode): mnemonic = "replace2"
class Replace3Opcode(ByteOpsOpcode): mnemonic = "replace3"
class LenOpcode(ByteOpsOpcode): mnemonic = "len"
class BitlenOpcode(ByteOpsOpcode): mnemonic = "bitlen"
class GetbitOpcode(ByteOpsOpcode): mnemonic = "getbit"
class SetbitOpcode(ByteOpsOpcode): mnemonic = "setbit"
class GetbyteOpcode(ByteOpsOpcode): mnemonic = "getbyte"
class SetbyteOpcode(ByteOpsOpcode): mnemonic = "setbyte"
class ItobOpcode(ByteOpsOpcode): mnemonic = "itob"
class BtoiOpcode(ByteOpsOpcode): mnemonic = "btoi"
class Base64DecodeOpcode(ByteOpsOpcode): mnemonic = "base64_decode"
class JsonRefOpcode(ByteOpsOpcode): mnemonic = "json_ref"


# ----- Family: Constants / pushes / block loads -----------------------------

class ConstantOpcode(Opcode): pass

class IntOpcode(ConstantOpcode): pass
class IntcblockOpcode(ConstantOpcode): mnemonic = "intcblock"
class IntcOpcode(ConstantOpcode): mnemonic = "intc"
class Intc0Opcode(ConstantOpcode): mnemonic = "intc_0"
class Intc1Opcode(ConstantOpcode): mnemonic = "intc_1"
class Intc2Opcode(ConstantOpcode): mnemonic = "intc_2"
class Intc3Opcode(ConstantOpcode): mnemonic = "intc_3"
class PushintOpcode(ConstantOpcode): mnemonic = "pushint"
class PushintsOpcode(ConstantOpcode): mnemonic = "pushints"
class BytecblockOpcode(ConstantOpcode): mnemonic = "bytecblock"
class BytecOpcode(ConstantOpcode): mnemonic = "bytec"
class Bytec0Opcode(ConstantOpcode): mnemonic = "bytec_0"
class Bytec1Opcode(ConstantOpcode): mnemonic = "bytec_1"
class Bytec2Opcode(ConstantOpcode): mnemonic = "bytec_2"
class Bytec3Opcode(ConstantOpcode): mnemonic = "bytec_3"
class PushbytesOpcode(ConstantOpcode): mnemonic = "pushbytes"
class PushbytessOpcode(ConstantOpcode): mnemonic = "pushbytess"
class BzeroOpcode(ConstantOpcode): mnemonic = "bzero"


# ----- Family: Control flow -------------------------------------------------

class ControlFlowOpcode(Opcode): pass
class BranchOpcode(ControlFlowOpcode): pass

class ContractExitOpcode(ControlFlowOpcode): pass
class ReturnOpcode(ControlFlowOpcode): mnemonic = "return"
class ErrOpcode(ControlFlowOpcode): mnemonic = "err"
class AssertOpcode(ControlFlowOpcode): mnemonic = "assert"
class BOpcode(BranchOpcode): mnemonic = "b"
class CallsubOpcode(BranchOpcode): mnemonic = "callsub"
class RetsubOpcode(ControlFlowOpcode): mnemonic = "retsub"
class BnzOpcode(BranchOpcode): mnemonic = "bnz"
class BzOpcode(BranchOpcode): mnemonic = "bz"
class SwitchOpcode(BranchOpcode): mnemonic = "switch"
class MatchOpcode(BranchOpcode): mnemonic = "match"


# ----- Family: Cryptography (signature verification) ------------------------

class CryptoOpcode(Opcode): pass

class Ed25519verifyOpcode(CryptoOpcode): mnemonic = "ed25519verify"
class Ed25519verifyBareOpcode(CryptoOpcode): mnemonic = "ed25519verify_bare"
class EcdsaVerifyOpcode(CryptoOpcode): mnemonic = "ecdsa_verify"
class EcdsaPkDecompressOpcode(CryptoOpcode): mnemonic = "ecdsa_pk_decompress"
class EcdsaPkRecoverOpcode(CryptoOpcode): mnemonic = "ecdsa_pk_recover"
class VrfVerifyOpcode(CryptoOpcode): mnemonic = "vrf_verify"


# ----- Family: Elliptic curve primitives ------------------------------------

class EllipticCurveOpcode(Opcode): pass

class EcAddOpcode(EllipticCurveOpcode): mnemonic = "ec_add"
class EcMulOpcode(EllipticCurveOpcode): mnemonic = "ec_scalar_mul"
class EcPairingCheckOpcode(EllipticCurveOpcode): mnemonic = "ec_pairing_check"
class EcMultiScalarMulOpcode(EllipticCurveOpcode): mnemonic = "ec_multi_scalar_mul"
class EcSubgroupCheckOpcode(EllipticCurveOpcode): mnemonic = "ec_subgroup_check"
class EcMapToOpcode(EllipticCurveOpcode): mnemonic = "ec_map_to"


# ----- Family: Hashing ------------------------------------------------------

class HashingOpcode(Opcode): pass

class Sha256Opcode(HashingOpcode): mnemonic = "sha256"
class Sha512_256Opcode(HashingOpcode): mnemonic = "sha512_256"
class Keccak256Opcode(HashingOpcode): mnemonic = "keccak256"
class Sha3_256Opcode(HashingOpcode): mnemonic = "sha3_256"
# AVM v13. NOT a variant of sha512_256: that is the TRUNCATED form with a different IV,
# so the two produce unrelated digests and a program using this one must not be silently
# read as using the other.
class Sha512Opcode(HashingOpcode): mnemonic = "sha512"
class MimcOpcode(HashingOpcode): mnemonic = "mimc"


# ----- Family: Global / application / asset / account state -----------------

class GlobalStateOpcode(Opcode): pass

class GlobalOpcode(GlobalStateOpcode): mnemonic = "global"
class AppOptedInOpcode(GlobalStateOpcode): mnemonic = "app_opted_in"
class AppLocalGetOpcode(GlobalStateOpcode): mnemonic = "app_local_get"
class AppLocalGetExOpcode(GlobalStateOpcode): mnemonic = "app_local_get_ex"
class AppGlobalGetOpcode(GlobalStateOpcode): mnemonic = "app_global_get"
class AppGlobalGetExOpcode(GlobalStateOpcode): mnemonic = "app_global_get_ex"
class AppLocalPutOpcode(GlobalStateOpcode): mnemonic = "app_local_put"
class AppGlobalPutOpcode(GlobalStateOpcode): mnemonic = "app_global_put"
class AppLocalDelOpcode(GlobalStateOpcode): mnemonic = "app_local_del"
class AppGlobalDelOpcode(GlobalStateOpcode): mnemonic = "app_global_del"
class AppParamsGetOpcode(GlobalStateOpcode): mnemonic = "app_params_get"
class AssetHoldingGetOpcode(GlobalStateOpcode): mnemonic = "asset_holding_get"
class AssetParamsGetOpcode(GlobalStateOpcode): mnemonic = "asset_params_get"
class AcctParamsGetOpcode(GlobalStateOpcode): mnemonic = "acct_params_get"
class BalanceOpcode(GlobalStateOpcode): mnemonic = "balance"
class MinBalanceOpcode(GlobalStateOpcode): mnemonic = "min_balance"
class OnlineStakeOpcode(GlobalStateOpcode): mnemonic = "online_stake"
class VoterParamsGetOpcode(GlobalStateOpcode): mnemonic = "voter_params_get"


# ----- Family: Box storage --------------------------------------------------

class BoxStorageOpcode(Opcode): pass

class BoxCreateOpcode(BoxStorageOpcode): mnemonic = "box_create"
class BoxExtractOpcode(BoxStorageOpcode): mnemonic = "box_extract"
class BoxReplaceOpcode(BoxStorageOpcode): mnemonic = "box_replace"
class BoxDelOpcode(BoxStorageOpcode): mnemonic = "box_del"
class BoxLenOpcode(BoxStorageOpcode): mnemonic = "box_len"
class BoxGetOpcode(BoxStorageOpcode): mnemonic = "box_get"
class BoxPutOpcode(BoxStorageOpcode): mnemonic = "box_put"
class BoxSpliceOpcode(BoxStorageOpcode): mnemonic = "box_splice"
class BoxResizeOpcode(BoxStorageOpcode): mnemonic = "box_resize"


# ----- Family: Transaction accessors ----------------------------------------

class TransactionOpcode(Opcode): pass

class TxnOpcode(TransactionOpcode): mnemonic = "txn"
class TxnaOpcode(TransactionOpcode): mnemonic = "txna"
class TxnasOpcode(TransactionOpcode): mnemonic = "txnas"
class GtxnOpcode(TransactionOpcode): mnemonic = "gtxn"
class GtxnaOpcode(TransactionOpcode): mnemonic = "gtxna"
class GtxnasOpcode(TransactionOpcode): mnemonic = "gtxnas"
class GtxnsOpcode(TransactionOpcode): mnemonic = "gtxns"
class GtxnsaOpcode(TransactionOpcode): mnemonic = "gtxnsa"
class GtxnsasOpcode(TransactionOpcode): mnemonic = "gtxnsas"
class GitxnOpcode(TransactionOpcode): mnemonic = "gitxn"
class GitxnaOpcode(TransactionOpcode): mnemonic = "gitxna"
class GitxnasOpcode(TransactionOpcode): mnemonic = "gitxnas"


# ----- Family: Inner transactions -------------------------------------------

class InnerTransactionOpcode(Opcode): pass
class InnerTransactionStart(InnerTransactionOpcode): pass  # begin | next
class InnerTransactionEnd(InnerTransactionOpcode): pass    # next  | submit

class ItxnOpcode(InnerTransactionOpcode): mnemonic = "itxn"
class ItxnaOpcode(InnerTransactionOpcode): mnemonic = "itxna"
class ItxnasOpcode(InnerTransactionOpcode): mnemonic = "itxnas"
class InnerTransactionField(InnerTransactionOpcode): mnemonic = "itxn_field"
class InnerTransactionBegin(InnerTransactionStart): mnemonic = "itxn_begin"
class InnerTransactionNext(InnerTransactionStart, InnerTransactionEnd): mnemonic = "itxn_next"
class InnerTransactionSubmit(InnerTransactionEnd): mnemonic = "itxn_submit"


# ----- Family: Logging ------------------------------------------------------

class LoggingOpcode(Opcode): pass

class LogOpcode(LoggingOpcode): mnemonic = "log"


# ----- Family: Scratch space ------------------------------------------------

class ScratchSpaceOpcode(Opcode): pass

class LoadOpcode(ScratchSpaceOpcode): mnemonic = "load"
class StoreOpcode(ScratchSpaceOpcode): mnemonic = "store"
class LoadsOpcode(ScratchSpaceOpcode): mnemonic = "loads"
class StoresOpcode(ScratchSpaceOpcode): mnemonic = "stores"
class GloadOpcode(ScratchSpaceOpcode): mnemonic = "gload"
class GloadsOpcode(ScratchSpaceOpcode): mnemonic = "gloads"
class GloadssOpcode(ScratchSpaceOpcode): mnemonic = "gloadss"
class GaidOpcode(ScratchSpaceOpcode): mnemonic = "gaid"
class GaidsOpcode(ScratchSpaceOpcode): mnemonic = "gaids"


# ----- Family: Stack manipulation -------------------------------------------

class StackManipulationOpcode(Opcode): pass

class DigOpcode(StackManipulationOpcode): mnemonic = "dig"
class ProtoOpcode(StackManipulationOpcode): mnemonic = "proto"
class PopOpcode(StackManipulationOpcode): mnemonic = "pop"
class PopnOpcode(StackManipulationOpcode): mnemonic = "popn"
class DupOpcode(StackManipulationOpcode): mnemonic = "dup"
class Dup2Opcode(StackManipulationOpcode): mnemonic = "dup2"
class DupnOpcode(StackManipulationOpcode): mnemonic = "dupn"
class SwapOpcode(StackManipulationOpcode): mnemonic = "swap"
class BuryOpcode(StackManipulationOpcode): mnemonic = "bury"
class CoverOpcode(StackManipulationOpcode): mnemonic = "cover"
class UncoverOpcode(StackManipulationOpcode): mnemonic = "uncover"
class FrameDigOpcode(StackManipulationOpcode): mnemonic = "frame_dig"
class FrameBuryOpcode(StackManipulationOpcode): mnemonic = "frame_bury"
class SelectOpcode(StackManipulationOpcode): mnemonic = "select"


# ----- Family: Misc (program args, block lookup) ----------------------------

class MiscOpcode(Opcode): pass

class ArgOpcode(MiscOpcode): mnemonic = "arg"
class Arg0Opcode(MiscOpcode): mnemonic = "arg_0"
class Arg1Opcode(MiscOpcode): mnemonic = "arg_1"
class Arg2Opcode(MiscOpcode): mnemonic = "arg_2"
class Arg3Opcode(MiscOpcode): mnemonic = "arg_3"
class ArgsOpcode(MiscOpcode): mnemonic = "args"
class BlockOpcode(MiscOpcode): mnemonic = "block"



# ----- Public surface -------------------------------------------------------

#: Every AST node type, plus `Location` and the mnemonic lookup. Explicit because
#: the package `__init__` star-imports this module: without it, `dataclass`,
#: `ClassVar`, `Optional` and `annotations` leak out as part of the AST API.
#: Computed from the hierarchy so adding an opcode cannot make it drift.
__all__ = ["Location", "node_class_for_mnemonic", *sorted(
    _name for _name, _obj in list(globals().items())
    if isinstance(_obj, type) and issubclass(_obj, AstNode)
)]
