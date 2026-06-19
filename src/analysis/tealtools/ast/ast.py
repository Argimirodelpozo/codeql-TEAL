"""Python class hierarchy mirroring TEAL AST node types.

Every class here corresponds to a CodeQL ``qlClass`` that can appear as a
node in the graphs produced by :mod:`tealtools.graphs`. Instances of these
classes are what :mod:`tealtools.graphs` stores as the NetworkX node objects,
so you get typed node inspection for free:

    >>> from tealtools.ast import IntegerAddOpcode, Opcode, ArithmeticOpcode
    >>> g = load_graph("tests/dbs/xgov-db")
    >>> [n for n in g if isinstance(n, IntegerAddOpcode)]
    >>> [n for n in g if isinstance(n, ArithmeticOpcode)]

Each node carries two fields:

- ``location``: a :class:`Location` from CodeQL (file + full start/end span)
- ``code``: the opcode with its immediates, as written in the source
  (e.g. ``"int 1"``, ``"load 2"``, ``"txna ApplicationArgs 0"``).

The hierarchy groups opcodes by the same families the original CodeQL TEAL
grammar used (``teal/ast/opcodes/``, since removed). Family classes
(``ArithmeticOpcode``, ``CryptoOpcode``, ...) are pure Python groupings —
they do not correspond to CodeQL ``qlClass`` strings and are never
instantiated directly by :func:`ast_node_from_row`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Location:
    """A CodeQL source-range location."""
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __str__(self) -> str:
        return f"{self.file}:{self.start_line}:{self.start_column}"


# ---------------------------------------------------------------------------
# Base class + registry
# ---------------------------------------------------------------------------

class AstNode:
    """Any TEAL AST node that can appear as a graph node.

    Hashing/equality are keyed by ``(file, start_line)`` — TEAL is
    one-instruction-per-line, so this uniquely identifies each node and
    lets edge endpoints (which CodeQL reports by ``(file, line)``) look
    up the matching node instance directly.
    """

    #: Registry of ``qlClass`` name -> concrete ``AstNode`` subclass.
    _registry: ClassVar[dict[str, type["AstNode"]]] = {}

    #: The ``getAPrimaryQlClass()`` string this class corresponds to.
    #: Subclasses inherit the class name unless they set this explicitly.
    ql_class: ClassVar[str] = "AstNode"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "ql_class" not in cls.__dict__:
            cls.ql_class = cls.__name__
        AstNode._registry.setdefault(cls.ql_class, cls)

    def __init__(self, location: Location, code: str):
        self.location = location
        self.code = code

    def __hash__(self) -> int:
        return hash((self.location.file, self.location.start_line))

    def __eq__(self, other) -> bool:
        if not isinstance(other, AstNode):
            return NotImplemented
        return (
            self.location.file == other.location.file
            and self.location.start_line == other.location.start_line
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.location.file}:{self.location.start_line})"


def ast_node_from_row(location: Location, code: str, ql_class: str) -> AstNode:
    """Construct the right :class:`AstNode` subclass for a CodeQL row.

    Falls back to a plain :class:`AstNode` when ``ql_class`` is unknown
    (new opcode, abstract class, grammar-only category, etc.).
    """
    cls = AstNode._registry.get(ql_class, AstNode)
    node = cls(location=location, code=code)
    if cls is AstNode:
        node.ql_class = ql_class
    return node


# ---------------------------------------------------------------------------
# Top-level groupings
# ---------------------------------------------------------------------------

class Opcode(AstNode):
    """Base class for every TEAL opcode."""


class NonOpcodeNode(AstNode):
    """Base for AST nodes that aren't opcodes (labels, comments, pragmas, ...)."""


# ---------------------------------------------------------------------------
# Non-opcode node kinds
# ---------------------------------------------------------------------------

class Label(NonOpcodeNode): pass
class LabelIdentifier(NonOpcodeNode): pass
class Comment(NonOpcodeNode): pass
class Token(NonOpcodeNode): pass
class ReservedWord(NonOpcodeNode): pass
class Source(NonOpcodeNode): pass

class PragmaVersion(NonOpcodeNode): pass
class PragmaTypetrack(NonOpcodeNode): pass

class NumericArgument(NonOpcodeNode): pass
class HexbytesArgument(NonOpcodeNode): pass
class StringArgument(NonOpcodeNode): pass

class ItxnFieldName(NonOpcodeNode): pass


# ---------------------------------------------------------------------------
# Argument-shape categories (tree-sitter buckets that some opcodes report as
# their primary ql class when they don't override ``getAPrimaryQlClass``)
# ---------------------------------------------------------------------------

class ZeroArgumentOpcode(Opcode): pass
class SingleNumericArgumentOpcode(Opcode): pass
class DoubleNumericArgumentOpcode(Opcode): pass


# ---------------------------------------------------------------------------
# Family: Arithmetic
# ---------------------------------------------------------------------------

class ArithmeticOpcode(Opcode): pass

class IntegerAddOpcode(ArithmeticOpcode): pass
class SubOpcode(ArithmeticOpcode): pass
class MulOpcode(ArithmeticOpcode): pass
class DivOpcode(ArithmeticOpcode): pass
class ModOpcode(ArithmeticOpcode): pass
class AddwOpcode(ArithmeticOpcode): pass
class MulwOpcode(ArithmeticOpcode): pass
class DivmodwOpcode(ArithmeticOpcode): pass
class ExpOpcode(ArithmeticOpcode): pass
class ExpwOpcode(ArithmeticOpcode): pass
class DivwOpcode(ArithmeticOpcode): pass
class SqrtOpcode(ArithmeticOpcode): pass
class ShlOpcode(ArithmeticOpcode): pass
class ShrOpcode(ArithmeticOpcode): pass


# ---------------------------------------------------------------------------
# Family: Byte arithmetic
# ---------------------------------------------------------------------------

class ByteArithmeticOpcode(Opcode): pass

class BaddOpcode(ByteArithmeticOpcode): pass
class BsubOpcode(ByteArithmeticOpcode): pass
class BdivOpcode(ByteArithmeticOpcode): pass
class BmulOpcode(ByteArithmeticOpcode): pass
class BmodOpcode(ByteArithmeticOpcode): pass
class BsqrtOpcode(ByteArithmeticOpcode): pass


# ---------------------------------------------------------------------------
# Family: Integer comparison + logical not
# ---------------------------------------------------------------------------

class ComparisonOpcode(Opcode): pass
class LogicalComparisonOp(ComparisonOpcode): pass

class EqualsComparisonOpcode(LogicalComparisonOp): pass
class NotEqualsComparisonOpcode(LogicalComparisonOp): pass
class NotOpcode(ComparisonOpcode): pass
class IntegerLessThanOpcode(ComparisonOpcode): pass
class IntegerLteOpcode(ComparisonOpcode): pass
class IntegerGreaterThanOpcode(ComparisonOpcode): pass
class IntegerGteOpcode(ComparisonOpcode): pass
class IntegerEqualsOpcode(ComparisonOpcode): pass
class IntegerNotEqualsOpcode(ComparisonOpcode): pass


# ---------------------------------------------------------------------------
# Family: Byte comparison
# ---------------------------------------------------------------------------

class ByteComparisonOpcode(Opcode): pass

class BltOpcode(ByteComparisonOpcode): pass
class BgtOpcode(ByteComparisonOpcode): pass
class BlteOpcode(ByteComparisonOpcode): pass
class BgteOpcode(ByteComparisonOpcode): pass
class BeqOpcode(ByteComparisonOpcode): pass
class BneqOpcode(ByteComparisonOpcode): pass


# ---------------------------------------------------------------------------
# Family: Logic (integer + byte bitwise)
# ---------------------------------------------------------------------------

class LogicOpcode(Opcode): pass

class AndOpcode(LogicOpcode): pass
class OrOpcode(LogicOpcode): pass
class BitandOpcode(LogicOpcode): pass
class BitorOpcode(LogicOpcode): pass
class BitxorOpcode(LogicOpcode): pass
class BitnotOpcode(LogicOpcode): pass
class BorOpcode(LogicOpcode): pass
class BandOpcode(LogicOpcode): pass
class BxorOpcode(LogicOpcode): pass
class BnotOpcode(LogicOpcode): pass


# ---------------------------------------------------------------------------
# Family: Byte-string operations
# ---------------------------------------------------------------------------

class ByteOpsOpcode(Opcode): pass

class ConcatOpcode(ByteOpsOpcode): pass
class SubstringOpcode(ByteOpsOpcode): pass
class Substring3Opcode(ByteOpsOpcode): pass
class ExtractOpcode(ByteOpsOpcode): pass
class Extract3Opcode(ByteOpsOpcode): pass
class ExtractUint16Opcode(ByteOpsOpcode): pass
class ExtractUint32Opcode(ByteOpsOpcode): pass
class ExtractUint64Opcode(ByteOpsOpcode): pass
class Replace2Opcode(ByteOpsOpcode): pass
class Replace3Opcode(ByteOpsOpcode): pass
class LenOpcode(ByteOpsOpcode): pass
class BitlenOpcode(ByteOpsOpcode): pass
class GetbitOpcode(ByteOpsOpcode): pass
class SetbitOpcode(ByteOpsOpcode): pass
class GetbyteOpcode(ByteOpsOpcode): pass
class SetbyteOpcode(ByteOpsOpcode): pass
class ItobOpcode(ByteOpsOpcode): pass
class BtoiOpcode(ByteOpsOpcode): pass
class Base64DecodeOpcode(ByteOpsOpcode): pass
class JsonRefOpcode(ByteOpsOpcode): pass


# ---------------------------------------------------------------------------
# Family: Constants / pushes / block loads
# ---------------------------------------------------------------------------

class ConstantOpcode(Opcode): pass

class IntOpcode(ConstantOpcode): pass
class IntcblockOpcode(ConstantOpcode): pass
class IntcOpcode(ConstantOpcode): pass
class Intc0Opcode(ConstantOpcode): pass
class Intc1Opcode(ConstantOpcode): pass
class Intc2Opcode(ConstantOpcode): pass
class Intc3Opcode(ConstantOpcode): pass
class PushintOpcode(ConstantOpcode): pass
class PushintsOpcode(ConstantOpcode): pass
class BytecblockOpcode(ConstantOpcode): pass
class BytecOpcode(ConstantOpcode): pass
class Bytec0Opcode(ConstantOpcode): pass
class Bytec1Opcode(ConstantOpcode): pass
class Bytec2Opcode(ConstantOpcode): pass
class Bytec3Opcode(ConstantOpcode): pass
class PushbytesOpcode(ConstantOpcode): pass
class PushbytessOpcode(ConstantOpcode): pass
class BzeroOpcode(ConstantOpcode): pass


# ---------------------------------------------------------------------------
# Family: Control flow
# ---------------------------------------------------------------------------

class ControlFlowOpcode(Opcode): pass
class BranchOpcode(ControlFlowOpcode): pass

class ContractExitOpcode(ControlFlowOpcode): pass
class ReturnOpcode(ControlFlowOpcode): pass
class ErrOpcode(ControlFlowOpcode): pass
class AssertOpcode(ControlFlowOpcode): pass
class BOpcode(BranchOpcode): pass
class CallsubOpcode(BranchOpcode): pass
class RetsubOpcode(ControlFlowOpcode): pass
class BnzOpcode(BranchOpcode): pass
class BzOpcode(BranchOpcode): pass
class SwitchOpcode(BranchOpcode): pass
class MatchOpcode(BranchOpcode): pass


# ---------------------------------------------------------------------------
# Family: Cryptography (signature verification)
# ---------------------------------------------------------------------------

class CryptoOpcode(Opcode): pass

class Ed25519verifyOpcode(CryptoOpcode): pass
class Ed25519verifyBareOpcode(CryptoOpcode): pass
class EcdsaVerifyOpcode(CryptoOpcode): pass
class EcdsaPkDecompressOpcode(CryptoOpcode): pass
class EcdsaPkRecoverOpcode(CryptoOpcode): pass
class VrfVerifyOpcode(CryptoOpcode): pass


# ---------------------------------------------------------------------------
# Family: Elliptic curve primitives
# ---------------------------------------------------------------------------

class EllipticCurveOpcode(Opcode): pass

class EcAddOpcode(EllipticCurveOpcode): pass
class EcMulOpcode(EllipticCurveOpcode): pass
class EcPairingCheckOpcode(EllipticCurveOpcode): pass
class EcMultiScalarMulOpcode(EllipticCurveOpcode): pass
class EcSubgroupCheckOpcode(EllipticCurveOpcode): pass
class EcMapToOpcode(EllipticCurveOpcode): pass


# ---------------------------------------------------------------------------
# Family: Hashing
# ---------------------------------------------------------------------------

class HashingOpcode(Opcode): pass

class Sha256Opcode(HashingOpcode): pass
class Sha512_256Opcode(HashingOpcode): pass
class Keccak256Opcode(HashingOpcode): pass
class Sha3_256Opcode(HashingOpcode): pass
class MimcOpcode(HashingOpcode): pass


# ---------------------------------------------------------------------------
# Family: Global / application / asset / account state
# ---------------------------------------------------------------------------

class GlobalStateOpcode(Opcode): pass

class GlobalOpcode(GlobalStateOpcode): pass
class AppOptedInOpcode(GlobalStateOpcode): pass
class AppLocalGetOpcode(GlobalStateOpcode): pass
class AppLocalGetExOpcode(GlobalStateOpcode): pass
class AppGlobalGetOpcode(GlobalStateOpcode): pass
class AppGlobalGetExOpcode(GlobalStateOpcode): pass
class AppLocalPutOpcode(GlobalStateOpcode): pass
class AppGlobalPutOpcode(GlobalStateOpcode): pass
class AppLocalDelOpcode(GlobalStateOpcode): pass
class AppGlobalDelOpcode(GlobalStateOpcode): pass
class AppParamsGetOpcode(GlobalStateOpcode): pass
class AssetHoldingGetOpcode(GlobalStateOpcode): pass
class AssetParamsGetOpcode(GlobalStateOpcode): pass
class AcctParamsGetOpcode(GlobalStateOpcode): pass
class BalanceOpcode(GlobalStateOpcode): pass
class MinBalanceOpcode(GlobalStateOpcode): pass
class OnlineStakeOpcode(GlobalStateOpcode): pass
class VoterParamsGetOpcode(GlobalStateOpcode): pass


# ---------------------------------------------------------------------------
# Family: Box storage
# ---------------------------------------------------------------------------

class BoxStorageOpcode(Opcode): pass

class BoxCreateOpcode(BoxStorageOpcode): pass
class BoxExtractOpcode(BoxStorageOpcode): pass
class BoxReplaceOpcode(BoxStorageOpcode): pass
class BoxDelOpcode(BoxStorageOpcode): pass
class BoxLenOpcode(BoxStorageOpcode): pass
class BoxGetOpcode(BoxStorageOpcode): pass
class BoxPutOpcode(BoxStorageOpcode): pass
class BoxSpliceOpcode(BoxStorageOpcode): pass
class BoxResizeOpcode(BoxStorageOpcode): pass


# ---------------------------------------------------------------------------
# Family: Transaction accessors
# ---------------------------------------------------------------------------

class TransactionOpcode(Opcode): pass

class TxnOpcode(TransactionOpcode): pass
class TxnaOpcode(TransactionOpcode): pass
class TxnasOpcode(TransactionOpcode): pass
class GtxnOpcode(TransactionOpcode): pass
class GtxnaOpcode(TransactionOpcode): pass
class GtxnasOpcode(TransactionOpcode): pass
class GtxnsOpcode(TransactionOpcode): pass
class GtxnsaOpcode(TransactionOpcode): pass
class GtxnsasOpcode(TransactionOpcode): pass
class GitxnOpcode(TransactionOpcode): pass
class GitxnaOpcode(TransactionOpcode): pass
class GitxnasOpcode(TransactionOpcode): pass


# ---------------------------------------------------------------------------
# Family: Inner transactions
# ---------------------------------------------------------------------------

class InnerTransactionOpcode(Opcode): pass
class InnerTransactionStart(InnerTransactionOpcode): pass  # begin | next
class InnerTransactionEnd(InnerTransactionOpcode): pass    # next  | submit

class ItxnOpcode(InnerTransactionOpcode): pass
class ItxnaOpcode(InnerTransactionOpcode): pass
class ItxnasOpcode(InnerTransactionOpcode): pass
class InnerTransactionField(InnerTransactionOpcode): pass
class InnerTransactionBegin(InnerTransactionStart): pass
class InnerTransactionNext(InnerTransactionStart, InnerTransactionEnd): pass
class InnerTransactionSubmit(InnerTransactionEnd): pass


# ---------------------------------------------------------------------------
# Family: Logging
# ---------------------------------------------------------------------------

class LoggingOpcode(Opcode): pass

class LogOpcode(LoggingOpcode): pass


# ---------------------------------------------------------------------------
# Family: Scratch space
# ---------------------------------------------------------------------------

class ScratchSpaceOpcode(Opcode): pass

class LoadOpcode(ScratchSpaceOpcode): pass
class StoreOpcode(ScratchSpaceOpcode): pass
class LoadsOpcode(ScratchSpaceOpcode): pass
class StoresOpcode(ScratchSpaceOpcode): pass
class GloadOpcode(ScratchSpaceOpcode): pass
class GloadsOpcode(ScratchSpaceOpcode): pass
class GloadssOpcode(ScratchSpaceOpcode): pass
class GaidOpcode(ScratchSpaceOpcode): pass
class GaidsOpcode(ScratchSpaceOpcode): pass


# ---------------------------------------------------------------------------
# Family: Stack manipulation
# ---------------------------------------------------------------------------

class StackManipulationOpcode(Opcode): pass

class DigOpcode(StackManipulationOpcode): pass
class ProtoOpcode(StackManipulationOpcode): pass
class PopOpcode(StackManipulationOpcode): pass
class PopnOpcode(StackManipulationOpcode): pass
class DupOpcode(StackManipulationOpcode): pass
class Dup2Opcode(StackManipulationOpcode): pass
class DupnOpcode(StackManipulationOpcode): pass
class SwapOpcode(StackManipulationOpcode): pass
class BuryOpcode(StackManipulationOpcode): pass
class CoverOpcode(StackManipulationOpcode): pass
class UncoverOpcode(StackManipulationOpcode): pass
class FrameDigOpcode(StackManipulationOpcode): pass
class FrameBuryOpcode(StackManipulationOpcode): pass
class SelectOpcode(StackManipulationOpcode): pass


# ---------------------------------------------------------------------------
# Family: Misc (program args, block lookup)
# ---------------------------------------------------------------------------

class MiscOpcode(Opcode): pass

class ArgOpcode(MiscOpcode): pass
class Arg0Opcode(MiscOpcode): pass
class Arg1Opcode(MiscOpcode): pass
class Arg2Opcode(MiscOpcode): pass
class Arg3Opcode(MiscOpcode): pass
class ArgsOpcode(MiscOpcode): pass
class BlockOpcode(MiscOpcode): pass


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def registered_ql_classes() -> list[str]:
    """Return every ``qlClass`` name handled by a dedicated subclass."""
    return sorted(AstNode._registry)
