"""Parse TEAL source into AST nodes.

Uses the ``tree-sitter-teal`` grammar (via the ``tree_sitter`` +
``tree_sitter_teal`` Python packages) to parse TEAL -- the grammar handles
semicolons, byte/string literals, labels, pragmas -- and emits one node per opcode
(plus ``Label`` nodes and the program-root ``Source`` node), each tagged with its
*most specific* :mod:`tealql.tealtools.ast` node type and source location.

Output shape per node:
``(file, startLine, startCol, endLine, endCol, node_type)``.

Key conventions:

* **Coordinates** — 1-based lines (``line = ts.row + 1``), tree-sitter's native
  0-based half-open columns (``start_col = ts.start_col``,
  ``end_col = ts.end_col``). Lines are 1-based because that's how editors /
  reports number TEAL; columns stay native (no off-by-one).
* **Type is keyed by the mnemonic** (the opcode's first child token), not
  the tree-sitter node type: generic buckets like ``zero_argument_opcode``
  cover ``==`` / ``+`` / ``return`` / ``dup`` … so the mnemonic decides.
* **One node per opcode.** Each opcode emits exactly one node of its most
  specific class. (Earlier ``==`` / ``!=`` each emitted two nodes — the
  typed and the generic comparison class — but the two collapse to one graph
  node by ``(file, line)`` and nothing downstream read the second, so it was
  dropped.)
* **`Source`** — the program root; emitted once, spanning ``(1,1)`` to the
  end of the last real (non-trivia) child (tree-sitter's root span includes
  the trailing newline, which the legacy extractor trimmed).
* **Skipped** — ``comment`` and ``pragma_*`` nodes (neither is emitted).

Each opcode class declares its own :attr:`~tealql.tealtools.ast.AstNode.mnemonic`
and auto-registers (:func:`node_class_for_mnemonic`), so the classes are the
single source of truth — there is no separate mnemonic→class string table.
The mnemonic assignments were originally derived by aligning tree-sitter
parses against the legacy node facts across 216 fixture contracts
(single-opcode lines only, to avoid cross-node pollution).
"""
from __future__ import annotations

import tree_sitter as _ts
import tree_sitter_teal as _tsteal

from ..cfg_build import _children, _program_cfg
from .ast import (
    AstNode, Label, Location, SingleNumericArgumentOpcode, Source,
    node_class_for_mnemonic,
)

_LANG = _ts.Language(_tsteal.language())

# tree-sitter Parser objects are NOT thread-safe (a shared one corrupts
# concurrent parses), and parallel corpus scans are a natural usage. Keep one
# Parser PER THREAD instead of a module-global; construction is cheap.
import threading as _threading

_PARSER_TLS = _threading.local()


def _parser() -> "_ts.Parser":
    p = getattr(_PARSER_TLS, "parser", None)
    if p is None:
        p = _PARSER_TLS.parser = _ts.Parser(_LANG)
    return p

# Tree-sitter child types that are not program statements / not emitted.
# Any ``pragma*`` node (``pragma_version`` / ``pragma_typetrack`` / ...) is
# also dropped — pragmas produce no rows. ``ERROR`` nodes are NOT trivia:
# they are unparseable source and are handled explicitly in
# :func:`parse_nodes` so the drop is *recorded* as a ParseDiagnostic
# instead of silently shrinking the program (a security scan of a
# partially-parsed contract must not read as "clean").
_TRIVIA = frozenset({"comment"})


def _is_trivia(node_type: str) -> bool:
    return node_type in _TRIVIA or node_type.startswith("pragma")


def _named_int_error(c) -> bool:
    """A tree-sitter ERROR that is really the ``int <NamedConstant>`` pseudo-op
    (``int DeleteApplication`` / ``int pay`` / …). The grammar's ``int`` rule
    only accepts a numeric argument, so the named OnCompletion / TxnType form
    parses as an ERROR and would be dropped as trivia — silently losing the
    pushed constant, so the comparison that consumes it loses an operand (the
    root cause of the named-constant guard blind spot). We recover it as an
    ``int`` opcode node; :mod:`const_values` resolves the name to its value."""
    return (
        c.type == "ERROR"
        and len(c.children) >= 2
        and c.children[0].type == "int"
        and c.children[1].type == "label_identifier"
    )

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
    """tree-sitter span -> ``(start_line, start_col, end_line, end_col)``:
    1-based lines, native 0-based half-open columns."""
    return (
        node.start_point[0] + 1,
        node.start_point[1],
        node.end_point[0] + 1,
        node.end_point[1],
    )


def parse_nodes(
    sources: dict[str, bytes | str],
    *,
    diagnostics: "list | None" = None,
) -> list:
    """Parse ``{file: source}`` into :class:`tealql.tealtools.ast.AstNode` objects.

    One node per opcode (plus ``Label`` nodes and the program-root ``Source``
    node), each with its source location and the source text of its line. The
    opcode's class comes from the mnemonic registry (:func:`node_class_for_mnemonic`).
    A ``Label`` is emitted only when it is a reachable CFG node (dead-subroutine
    entry labels are dropped) -- gated by the control-flow reachability over the
    opcode+label set.

    ``diagnostics``: optional accumulator. Every top-level tree-sitter
    ``ERROR`` span (unparseable source, other than the recovered
    ``int <NamedConstant>`` form) is DROPPED from the node stream; when an
    accumulator is passed, each drop appends a
    :class:`tealql.tealtools.errors.ParseDiagnostic` so callers can tell a fully-
    parsed program from a partial one.
    """
    from ..errors import ParseDiagnostic
    from ..graph import _slice_source        # lazy: graph imports this module
    out: list = []
    for file, src in sources.items():
        if isinstance(src, str):
            src = src.encode("utf-8")
        root = _parser().parse(src).root_node

        real: list = []
        for c in root.children:
            if _named_int_error(c):
                real.append(c)
            elif c.type == "ERROR":
                if diagnostics is not None:
                    text = src[c.start_byte:c.end_byte].decode("utf-8", "replace")
                    snippet = text.splitlines()[0].strip()[:80] if text.strip() else ""
                    diagnostics.append(ParseDiagnostic(
                        file=file,
                        start_line=c.start_point[0] + 1,
                        end_line=c.end_point[0] + 1,
                        snippet=snippet,
                    ))
            elif not _is_trivia(c.type):
                real.append(c)
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
            if _named_int_error(ch):
                # Recovered `int <name>`: span the `int` token through the named
                # identifier (tight, robust to greedy ERROR recovery), emit as
                # the same opcode class a numeric `int N` gets.
                a, b = ch.children[0], ch.children[1]
                op_nodes.append(_node(
                    a.start_point[0] + 1, a.start_point[1],
                    b.end_point[0] + 1, b.end_point[1],
                    SingleNumericArgumentOpcode))
                continue
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

        # Source node: the whole program, (line 1, col 0) .. the end of the
        # last real child (native half-open columns).
        last = real[-1]
        out.append(_node(1, 0, last.end_point[0] + 1, last.end_point[1], Source))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
