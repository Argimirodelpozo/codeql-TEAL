"""Parse TEAL source into AST nodes.

Uses the ``tree-sitter-teal`` grammar (via the ``tree_sitter`` +
``tree_sitter_teal`` Python packages) to parse TEAL -- the grammar handles
semicolons, byte/string literals, labels, pragmas -- and emits one node per opcode
(plus ``Label`` nodes and the program-root ``Source`` node), each tagged with its
*most specific* :mod:`tealtools.ast` node type and source location.

Output shape per node:
``(file, startLine, startCol, endLine, endCol, node_type)``.

Key conventions:

* **Columns** — tree-sitter points are 0-based half-open ``[start, end)``; we emit
  1-based closed ``[start, end]``: ``start_col = ts.start_col + 1``,
  ``end_col = ts.end_col``, ``line = ts.row + 1``.
* **Type is keyed by the mnemonic** (the opcode's first child token), not
  the tree-sitter node type: generic buckets like ``zero_argument_opcode``
  cover ``==`` / ``+`` / ``return`` / ``dup`` … so the mnemonic decides.
* **One node per opcode.** Each opcode emits exactly one node of its most
  specific class. (Earlier this reproduced a CodeQL artifact where ``==`` /
  ``!=`` each emitted two nodes — the typed and the generic comparison class
  — but the two collapse to one graph node by ``(file, line)`` and nothing
  downstream read the second, so it was dropped.)
* **`Source`** — the program root; emitted once, spanning ``(1,1)`` to the
  end of the last real (non-trivia) child (tree-sitter's root span includes
  the trailing newline, which the legacy extractor trimmed).
* **Skipped** — ``comment`` and ``pragma_*`` nodes (neither is emitted).

The mnemonic→class table was derived by aligning tree-sitter parses against
the legacy node facts across 216 fixture contracts (single-opcode lines
only, to avoid cross-node pollution).
"""
from __future__ import annotations

import tree_sitter as _ts
import tree_sitter_teal as _tsteal

from ..control_flow import _children, _program_cfg
from .ast import Location, ast_node_for_class

_LANG = _ts.Language(_tsteal.language())
_PARSER = _ts.Parser(_LANG)

# Tree-sitter child types that are not program statements / not emitted.
# Any ``pragma*`` node (``pragma_version`` / ``pragma_typetrack`` / ...) is
# also dropped — QL emits no pragma rows.
_TRIVIA = frozenset({"comment", "ERROR"})


def _is_trivia(node_type: str) -> bool:
    return node_type in _TRIVIA or node_type.startswith("pragma")

# mnemonic -> [QL leaf class names]. Derived from the corpus + the QL class
# hierarchy; ``==`` / ``!=`` are the only dual-class mnemonics.
MNEMONIC_CLASSES: dict[str, list[str]] = {
    '!': ['NotOpcode'],
    '!=': ['IntegerNotEqualsOpcode'],
    '%': ['ModOpcode'],
    '&&': ['AndOpcode'],
    '*': ['MulOpcode'],
    '+': ['IntegerAddOpcode'],
    '-': ['SubOpcode'],
    '/': ['DivOpcode'],
    '<': ['IntegerLessThanOpcode'],
    '<=': ['IntegerLteOpcode'],
    '==': ['EqualsComparisonOpcode'],
    '>': ['IntegerGreaterThanOpcode'],
    '>=': ['IntegerGteOpcode'],
    'acct_params_get': ['AcctParamsGetOpcode'],
    'addw': ['AddwOpcode'],
    'app_global_del': ['AppGlobalDelOpcode'],
    'app_global_get': ['AppGlobalGetOpcode'],
    'app_global_get_ex': ['AppGlobalGetExOpcode'],
    'app_global_put': ['AppGlobalPutOpcode'],
    'app_local_del': ['AppLocalDelOpcode'],
    'app_local_get': ['AppLocalGetOpcode'],
    'app_local_get_ex': ['AppLocalGetExOpcode'],
    'app_local_put': ['AppLocalPutOpcode'],
    'app_opted_in': ['AppOptedInOpcode'],
    'app_params_get': ['AppParamsGetOpcode'],
    'assert': ['AssertOpcode'],
    'asset_holding_get': ['AssetHoldingGetOpcode'],
    'asset_params_get': ['AssetParamsGetOpcode'],
    'b': ['BOpcode'],
    'b!=': ['BneqOpcode'],
    'b%': ['BmodOpcode'],
    'b&': ['BandOpcode'],
    'b*': ['BmulOpcode'],
    'b+': ['BaddOpcode'],
    'b-': ['BsubOpcode'],
    'b/': ['BdivOpcode'],
    'b<': ['BltOpcode'],
    'b<=': ['BlteOpcode'],
    'b==': ['BeqOpcode'],
    'b>': ['BgtOpcode'],
    'b>=': ['BgteOpcode'],
    'b^': ['BxorOpcode'],
    'balance': ['BalanceOpcode'],
    'base64_decode': ['Base64DecodeOpcode'],
    'bitlen': ['BitlenOpcode'],
    'block': ['BlockOpcode'],
    'bnz': ['BnzOpcode'],
    'box_create': ['BoxCreateOpcode'],
    'box_del': ['BoxDelOpcode'],
    'box_extract': ['BoxExtractOpcode'],
    'box_get': ['BoxGetOpcode'],
    'box_len': ['BoxLenOpcode'],
    'box_put': ['BoxPutOpcode'],
    'box_replace': ['BoxReplaceOpcode'],
    'box_resize': ['BoxResizeOpcode'],
    'box_splice': ['BoxSpliceOpcode'],
    'bsqrt': ['BsqrtOpcode'],
    'btoi': ['BtoiOpcode'],
    'bury': ['BuryOpcode'],
    'bytec': ['BytecOpcode'],
    'bytec_0': ['Bytec0Opcode'],
    'bytec_1': ['Bytec1Opcode'],
    'bytec_2': ['Bytec2Opcode'],
    'bytec_3': ['Bytec3Opcode'],
    'bytecblock': ['BytecblockOpcode'],
    'bz': ['BzOpcode'],
    'bzero': ['BzeroOpcode'],
    'b|': ['BorOpcode'],
    'callsub': ['CallsubOpcode'],
    'concat': ['ConcatOpcode'],
    'cover': ['CoverOpcode'],
    'dig': ['DigOpcode'],
    'divmodw': ['DivmodwOpcode'],
    'divw': ['DivwOpcode'],
    'dup': ['DupOpcode'],
    'dup2': ['Dup2Opcode'],
    'dupn': ['DupnOpcode'],
    'ed25519verify_bare': ['Ed25519verifyBareOpcode'],
    'err': ['ErrOpcode'],
    'exp': ['ExpOpcode'],
    'expw': ['ExpwOpcode'],
    'extract': ['ExtractOpcode'],
    'extract3': ['Extract3Opcode'],
    'extract_uint16': ['ExtractUint16Opcode'],
    'extract_uint32': ['ExtractUint32Opcode'],
    'extract_uint64': ['ExtractUint64Opcode'],
    'frame_bury': ['FrameBuryOpcode'],
    'frame_dig': ['FrameDigOpcode'],
    'gaid': ['GaidOpcode'],
    'gaids': ['GaidsOpcode'],
    'getbit': ['GetbitOpcode'],
    'getbyte': ['GetbyteOpcode'],
    'gitxn': ['GitxnOpcode'],
    'gitxna': ['GitxnaOpcode'],
    'gitxnas': ['GitxnasOpcode'],
    'gload': ['GloadOpcode'],
    'gloads': ['GloadsOpcode'],
    'gloadss': ['GloadssOpcode'],
    'global': ['GlobalOpcode'],
    'gtxn': ['GtxnOpcode'],
    'gtxna': ['GtxnaOpcode'],
    'gtxnas': ['GtxnasOpcode'],
    'gtxns': ['GtxnsOpcode'],
    'gtxnsa': ['GtxnsaOpcode'],
    'gtxnsas': ['GtxnsasOpcode'],
    'intc': ['IntcOpcode'],
    'intc_0': ['Intc0Opcode'],
    'intc_1': ['Intc1Opcode'],
    'intc_2': ['Intc2Opcode'],
    'intc_3': ['Intc3Opcode'],
    'intcblock': ['IntcblockOpcode'],
    'itob': ['ItobOpcode'],
    'itxn': ['ItxnOpcode'],
    'itxn_begin': ['InnerTransactionBegin'],
    'itxn_field': ['InnerTransactionField'],
    'itxn_next': ['InnerTransactionNext'],
    'itxn_submit': ['InnerTransactionSubmit'],
    'itxna': ['ItxnaOpcode'],
    'itxnas': ['ItxnasOpcode'],
    'keccak256': ['Keccak256Opcode'],
    'len': ['LenOpcode'],
    'load': ['LoadOpcode'],
    'loads': ['LoadsOpcode'],
    'log': ['LogOpcode'],
    'match': ['MatchOpcode'],
    'min_balance': ['MinBalanceOpcode'],
    'mulw': ['MulwOpcode'],
    'pop': ['PopOpcode'],
    'popn': ['PopnOpcode'],
    'proto': ['ProtoOpcode'],
    'pushbytes': ['PushbytesOpcode'],
    'pushbytess': ['PushbytessOpcode'],
    'pushint': ['PushintOpcode'],
    'pushints': ['PushintsOpcode'],
    'replace2': ['Replace2Opcode'],
    'replace3': ['Replace3Opcode'],
    'retsub': ['RetsubOpcode'],
    'return': ['ReturnOpcode'],
    'select': ['SelectOpcode'],
    'setbit': ['SetbitOpcode'],
    'setbyte': ['SetbyteOpcode'],
    'sha256': ['Sha256Opcode'],
    'sha3_256': ['Sha3_256Opcode'],
    'sha512_256': ['Sha512_256Opcode'],
    'shl': ['ShlOpcode'],
    'shr': ['ShrOpcode'],
    'sqrt': ['SqrtOpcode'],
    'store': ['StoreOpcode'],
    'stores': ['StoresOpcode'],
    'substring': ['SubstringOpcode'],
    'substring3': ['Substring3Opcode'],
    'swap': ['SwapOpcode'],
    'switch': ['SwitchOpcode'],
    'txn': ['TxnOpcode'],
    'txna': ['TxnaOpcode'],
    'txnas': ['TxnasOpcode'],
    'uncover': ['UncoverOpcode'],
    'vrf_verify': ['VrfVerifyOpcode'],
    '||': ['OrOpcode'],
    '~': ['BitnotOpcode'],
}

# Opcodes not present in the fixture corpus, so not corpus-derived above, but
# real AVM ops that appear in the behavioural mainnet corpus. Mnemonic→class
# follows the same QL naming convention; not covered by the parity test (the
# fixtures don't exercise them), so treat as best-effort until a DB does.
_SUPPLEMENT: dict[str, list[str]] = {
    '&': ['BitandOpcode'],
    '|': ['BitorOpcode'],
    '^': ['BitxorOpcode'],
    'arg': ['ArgOpcode'],
    'arg_0': ['Arg0Opcode'],
    'arg_1': ['Arg1Opcode'],
    'arg_2': ['Arg2Opcode'],
    'arg_3': ['Arg3Opcode'],
    'args': ['ArgsOpcode'],
    'json_ref': ['JsonRefOpcode'],
    'mimc': ['MimcOpcode'],
    'online_stake': ['OnlineStakeOpcode'],
    'voter_params_get': ['VoterParamsGetOpcode'],
    'ed25519verify': ['Ed25519verifyOpcode'],
    'ecdsa_verify': ['EcdsaVerifyOpcode'],
    'ecdsa_pk_decompress': ['EcdsaPkDecompressOpcode'],
    'ecdsa_pk_recover': ['EcdsaPkRecoverOpcode'],
}

_CLASSES = {**_SUPPLEMENT, **MNEMONIC_CLASSES}


def _ts_to_pascal(node_type: str) -> str:
    """Fallback class for an opcode whose mnemonic isn't in the table:
    PascalCase the tree-sitter node type (``txn_opcode`` -> ``TxnOpcode``).
    Faithful for specifically-typed grammar nodes; for generic buckets it
    yields the bucket class, which is what QL falls back to only when no
    leaf matches."""
    return "".join(p.capitalize() for p in node_type.split("_"))


def _classes_for(child) -> list[str]:
    mnem = child.children[0].type if child.children else child.type
    cls = _CLASSES.get(mnem)
    if cls is not None:
        return cls
    return [_ts_to_pascal(child.type)]


def _loc(node) -> tuple[int, int, int, int]:
    """tree-sitter span -> CodeQL (startLine, startCol, endLine, endCol)."""
    return (
        node.start_point[0] + 1,
        node.start_point[1] + 1,
        node.end_point[0] + 1,
        node.end_point[1],
    )


def parse_nodes(sources: dict[str, bytes | str]) -> list:
    """Parse ``{file: source}`` into :class:`tealtools.ast.AstNode` objects.

    One node per opcode (plus ``Label`` nodes and the program-root ``Source``
    node), each with its source location and the source text of its line.
    ``==`` / ``!=`` yield two nodes (one per matched leaf type); a ``Label`` is
    emitted only when it is a reachable CFG node (dead-subroutine entry labels are
    dropped) -- gated by the control-flow reachability over the opcode+label set.
    """
    from ..graph import _slice_source        # lazy: graph imports this module
    out: list = []
    for file, src in sources.items():
        if isinstance(src, str):
            src = src.encode("utf-8")
        root = _PARSER.parse(src).root_node

        real = [c for c in root.children if not _is_trivia(c.type)]
        if not real:
            continue

        slines = {file: src.decode("utf-8", "replace").splitlines()}

        def _node(sl, sc, el, ec, cls):
            loc = Location(file, sl, sc, el, ec)
            return ast_node_for_class(loc, _slice_source(slines, loc).strip(), cls)

        # All opcode nodes are emitted; label nodes are reachability-gated below.
        op_nodes: list = []
        label_nodes: list = []
        for ch in real:
            sl, sc, el, ec = _loc(ch)
            if ch.type == "label":
                label_nodes.append(_node(sl, sc, el, ec, "Label"))
            else:
                for cls in _classes_for(ch):
                    op_nodes.append(_node(sl, sc, el, ec, cls))

        reach_lines: set[int] = set()
        kids = _children(op_nodes + label_nodes).get(file, [])
        if kids:
            _cand, reachable, _idx = _program_cfg(kids)
            reach_lines = {kids[i].line for i in reachable}

        # Source node: (1,1) .. end of the last real child, extended one column to
        # the line terminator IF the file's last content line ends with a newline
        # (the program spans through that terminator). No trailing newline (e.g.
        # xgov) -> ends exactly at the last token; one (the folks contracts) -> one
        # column past it.
        last = real[-1]
        end_col = last.end_point[1] + (1 if b"\n" in src[last.end_byte:] else 0)
        out.append(_node(1, 1, last.end_point[0] + 1, end_col, "Source"))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
