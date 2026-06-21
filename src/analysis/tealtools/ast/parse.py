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

Each opcode class declares its own :attr:`~tealtools.ast.AstNode.mnemonic`
and auto-registers (:func:`node_class_for_mnemonic`), so the classes are the
single source of truth — there is no separate mnemonic→class string table.
The mnemonic assignments were originally derived by aligning tree-sitter
parses against the legacy node facts across 216 fixture contracts
(single-opcode lines only, to avoid cross-node pollution).
"""
from __future__ import annotations

import tree_sitter as _ts
import tree_sitter_teal as _tsteal

from ..control_flow import _children, _program_cfg
from .ast import AstNode, Label, Location, Source, node_class_for_mnemonic

_LANG = _ts.Language(_tsteal.language())
_PARSER = _ts.Parser(_LANG)

# Tree-sitter child types that are not program statements / not emitted.
# Any ``pragma*`` node (``pragma_version`` / ``pragma_typetrack`` / ...) is
# also dropped — QL emits no pragma rows.
_TRIVIA = frozenset({"comment", "ERROR"})


def _is_trivia(node_type: str) -> bool:
    return node_type in _TRIVIA or node_type.startswith("pragma")

def _ts_to_pascal(node_type: str) -> str:
    """Fallback node-class for an opcode whose mnemonic no class claims:
    PascalCase the tree-sitter node type (``txn_opcode`` -> ``TxnOpcode``).
    Faithful for specifically-typed grammar nodes; for generic buckets it
    yields the bucket class."""
    return "".join(p.capitalize() for p in node_type.split("_"))


def _class_for(child) -> tuple[type, "str | None"]:
    """The :class:`AstNode` subclass to instantiate for an opcode ``child``,
    and an optional ``node_class`` override used only for the bare-:class:`AstNode`
    fallback. Resolution: the mnemonic registry (each opcode class declares its
    own :attr:`mnemonic`), else the tree-sitter PascalCase node-class, else a
    plain ``AstNode`` tagged with that name."""
    mnem = child.children[0].type if child.children else child.type
    cls = node_class_for_mnemonic(mnem)
    if cls is not None:
        return cls, None
    pascal = _ts_to_pascal(child.type)
    by_name = AstNode._registry.get(pascal)
    if by_name is not None:
        return by_name, None
    return AstNode, pascal


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
    node), each with its source location and the source text of its line. The
    opcode's class comes from the mnemonic registry (:func:`node_class_for_mnemonic`).
    A ``Label`` is emitted only when it is a reachable CFG node (dead-subroutine
    entry labels are dropped) -- gated by the control-flow reachability over the
    opcode+label set.
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

        def _node(sl, sc, el, ec, cls, override=None):
            loc = Location(file, sl, sc, el, ec)
            n = cls(location=loc, code=_slice_source(slines, loc).strip())
            if override is not None:
                n.node_class = override
            return n

        # All opcode nodes are emitted; label nodes are reachability-gated below.
        op_nodes: list = []
        label_nodes: list = []
        for ch in real:
            sl, sc, el, ec = _loc(ch)
            if ch.type == "label":
                label_nodes.append(_node(sl, sc, el, ec, Label))
            else:
                cls, override = _class_for(ch)
                op_nodes.append(_node(sl, sc, el, ec, cls, override))

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
        out.append(_node(1, 1, last.end_point[0] + 1, end_col, Source))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
