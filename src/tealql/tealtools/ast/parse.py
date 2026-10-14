"""Parse TEAL source into :mod:`tealql.tealtools.ast` nodes via ``tree-sitter-teal``.

Emits one node per opcode, plus ``Label`` nodes and the program-root ``Source``
node (spanning line 1 to the end of the last non-trivia child); ``comment`` and
``pragma_*`` are skipped.

HAZARD — coordinates: lines are 1-based (``ts.row + 1``), columns stay
tree-sitter-native 0-based half-open. Mixing the two conventions is an
off-by-one in every reported location.

A node's class is keyed by the MNEMONIC (its first child token), never by the
tree-sitter node type: generic buckets like ``zero_argument_opcode`` cover
``==`` / ``+`` / ``return`` / ``dup`` alike. Each opcode class declares its own
:attr:`~tealql.tealtools.ast.AstNode.mnemonic` and auto-registers
(:func:`node_class_for_mnemonic`), so the classes are the single source of truth.
"""
from __future__ import annotations

import tree_sitter as _ts
import tree_sitter_teal as _tsteal

from ..cfg.build import _children, _program_cfg
from .ast import AstNode, Label, Location, Source, node_class_for_mnemonic

_LANG = _ts.Language(_tsteal.language())

# One Parser PER THREAD: tree-sitter Parsers are not thread-safe (a shared one
# corrupts concurrent parses) and parallel corpus scans are normal usage.
import threading as _threading

_PARSER_TLS = _threading.local()


def _parser() -> "_ts.Parser":
    p = getattr(_PARSER_TLS, "parser", None)
    if p is None:
        p = _PARSER_TLS.parser = _ts.Parser(_LANG)
    return p

# Non-statement child types, dropped silently (any ``pragma*`` too). ERROR is
# NOT trivia: it is unparseable source, handled in :func:`parse_nodes` so the
# drop is RECORDED — a scan of a partially-parsed contract must not read clean.
_TRIVIA = frozenset({"comment"})


def _is_trivia(node_type: str) -> bool:
    return node_type in _TRIVIA or node_type.startswith("pragma")


#: Nodes that ARE source but cannot be emitted as an instruction: a mnemonic the
#: grammar does not know (``unknown_opcode``), and an assembler pseudo-op that
#: the graph layer's normalisation could not resolve to its canonical push (an
#: ``addr`` with a bad checksum, an unquoted ``method`` signature, ...). Each is
#: DROPPED with a diagnostic, exactly like an ``ERROR`` span.
_UNEMITTABLE = {
    "unknown_opcode": "unknown opcode",
    "byte_pseudo_opcode": "unresolvable byte constant",
    "addr_pseudo_opcode": "invalid address constant",
    "method_pseudo_opcode": "unresolvable method selector",
}


def _diagnostic_for(c, src: bytes, file: str, reason: "str | None" = None):
    """The ``ParseDiagnostic`` recording that node ``c`` was DROPPED."""
    from ..diagnostics.errors import ParseDiagnostic
    text = src[c.start_byte:c.end_byte].decode("utf-8", "replace")
    snippet = text.splitlines()[0].strip()[:80] if text.strip() else ""
    if reason is not None:
        snippet = f"{reason} {snippet!r} was DROPPED"
    return ParseDiagnostic(file=file, start_line=c.start_point[0] + 1,
                           end_line=c.end_point[0] + 1, snippet=snippet)


def _unavailable_at(node, version: "int | None") -> "str | None":
    """Why ``node`` cannot assemble at ``#pragma version <version>``, or ``None``.

    The grammar accepts the whole pinned spec (AVM v13) regardless of the
    program's version; the assembler does not. An opcode, or a field immediate,
    introduced after the declared version is rejected by goal, so it is dropped
    with a diagnostic rather than analysed as if the program could contain it.
    SCOPE: only the opcodes the pinned Puya cannot represent
    (``PUYA_57_UNSUPPORTED``: ``app_box_*``, ``poseidon2``, ``app_params_set``)
    are gated, as before this grammar knew them -- a program without a pragma
    counts as version 1 for them. Gating every opcode is a semantic change of
    its own (committed hand-written fixtures use ops above their pragma)."""
    if node.type == "label" or not node.children:
        return None
    from ..language.spec import PUYA_57_UNSUPPORTED, opcode_spec
    mnem = node.children[0].type
    if mnem not in PUYA_57_UNSUPPORTED:
        return None
    version = 1 if version is None else version
    latest = opcode_spec(mnem)
    if latest is None:
        return None                       # a pseudo-op (`int`, bare `extract`, ...)
    if opcode_spec(mnem, version) is None:
        return f"{mnem} is not available at version {version}:"
    for k in node.children[1:]:
        # The LATEST spec's field table: the versioned one simply omits a field
        # introduced later, which must read as unavailable, not as unknown.
        detail = latest.fields.get(k.type) if not k.is_named else None
        if detail is not None and detail[1] > version:
            return f"field {k.type} is not available at version {version}:"
    return None


def _ts_to_pascal(node_type: str) -> str:
    """PascalCase a tree-sitter node type (``txn_opcode`` -> ``TxnOpcode``) as the
    fallback class for an opcode whose mnemonic no class claims."""
    return "".join(p.capitalize() for p in node_type.split("_"))


def _class_for(child) -> tuple[type, "str | None"]:
    """``(AstNode subclass, node_class override)`` for an opcode child: mnemonic
    registry first, else the PascalCase node-class, else a tagged ``AstNode``."""
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
    """tree-sitter span -> ``(start_line, start_col, end_line, end_col)`` — 1-based
    lines, native 0-based half-open columns."""
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

    A ``Label`` is emitted only if reachable in the CFG over the opcode+label set
    (dead-subroutine entry labels are dropped).

    HAZARD: every unrecovered ``ERROR`` span is DROPPED from the node stream, as
    are extra instructions on a shared line and duplicate labels. Each drop
    appends a :class:`tealql.tealtools.diagnostics.errors.ParseDiagnostic` to ``diagnostics``
    when one is passed — the ONLY way a caller can tell a fully-parsed program
    from a partial one."""
    from ..diagnostics.errors import ParseDiagnostic
    from ..frontend.graph import _slice_source        # lazy: graph imports this module
    out: list = []
    for file, src in sources.items():
        if isinstance(src, str):
            src = src.encode("utf-8")
        root = _parser().parse(src).root_node

        # Every top-level child is ONE statement, a label, trivia, or a span the
        # grammar could not parse. Newlines are significant in the grammar, so
        # an instruction ends at its line and a malformed one cannot swallow
        # the next.
        real: list = []
        version = None
        dropped = False
        for c in root.children:
            if c.type == "pragma_version" and not c.has_error:
                # The version is an anonymous token (no field node to fetch).
                text = src[c.start_byte:c.end_byte].split()[-1]
                version = int(text) if text.isdigit() else version
            if c.type == "ERROR" or c.has_error:
                # A MISSING immediate (`poseidon2` with no configuration) is an
                # error INSIDE an otherwise well-formed node: dropped too, never
                # emitted as an instruction with a hole in it.
                dropped = True
                if diagnostics is not None:
                    diagnostics.append(_diagnostic_for(c, src, file))
            elif c.type in _UNEMITTABLE:
                dropped = True
                if diagnostics is not None:
                    diagnostics.append(_diagnostic_for(c, src, file, _UNEMITTABLE[c.type]))
            elif not _is_trivia(c.type):
                unavailable = _unavailable_at(c, version)
                if unavailable is not None:
                    if diagnostics is not None:
                        diagnostics.append(_diagnostic_for(c, src, file, unavailable))
                    continue
                real.append(c)
        if root.has_error and not dropped and diagnostics is not None:
            # Recovery INVENTED a hidden token (a statement separator) between
            # two otherwise well-formed nodes. It has no node to point at, so
            # the file as a whole is flagged rather than read as clean.
            diagnostics.append(ParseDiagnostic(
                file=file, start_line=1, end_line=root.end_point[0] + 1,
                snippet="the parser recovered by inserting a missing token; "
                        "some instruction is malformed"))
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

        # HAZARD: one instruction per line is ARCHITECTURAL, not stylistic —
        # AstNode identity, SSAVar identity (file, line, index), the
        # scratch/cost/graph indexes and every violation are keyed by
        # (file, line). TEAL allows `int 1; int 2`, which COLLAPSES to a single
        # node (extra pushes vanish, the consumer loses operands). We cannot
        # represent it, so it is reported like unparseable source.
        if diagnostics is not None:
            # The mirror image of the same architectural rule: a node whose span
            # COVERS later lines has swallowed them. The grammar ends every
            # instruction at its newline, so this guards against a grammar
            # regression; it is never an expected path.
            for n in op_nodes:
                if n.location.end_line > n.location.start_line:
                    head = (((n.code or "").splitlines() or [""])[0].strip()
                            or n.node_class)
                    diagnostics.append(ParseDiagnostic(
                        file=file,
                        start_line=n.location.start_line,
                        end_line=n.location.end_line,
                        snippet=(f"{head!r} spans lines {n.location.start_line}-"
                                 f"{n.location.end_line}: the following line(s) were "
                                 "absorbed as its operands and are MISSING from "
                                 "analysis"),
                    ))
            by_line: dict[int, list] = {}
            for n in op_nodes:
                by_line.setdefault(n.location.start_line, []).append(n)
            for ln, group in sorted(by_line.items()):
                if len(group) > 1:
                    diagnostics.append(ParseDiagnostic(
                        file=file, start_line=ln, end_line=ln,
                        snippet=(f"{len(group)} instructions on one line "
                                 f"(only the first is analyzed): "
                                 f"{'; '.join(g.code for g in group)[:80]}"),
                    ))
            # Duplicate labels: the assembler rejects them, and branch resolution
            # picks one target, so the other block is pruned as unreachable.
            seen_labels: dict[str, int] = {}
            for n in label_nodes:
                nm = n.code.rstrip(":").strip()
                if nm in seen_labels:
                    diagnostics.append(ParseDiagnostic(
                        file=file,
                        start_line=n.location.start_line,
                        end_line=n.location.start_line,
                        snippet=(f"duplicate label {nm!r} (first defined at "
                                 f"line {seen_labels[nm]}; branches resolve to "
                                 f"that one and this block is unreachable)"),
                    ))
                else:
                    seen_labels[nm] = n.location.start_line

        reach_lines: set[int] = set()
        kids = _children(op_nodes + label_nodes).get(file, [])
        if kids:
            # This is the one CFG walk that sees EVERY label — the emit below
            # drops unreachable ones — so it is the only place holding the true
            # label universe, and therefore where a target naming no label at
            # all can be told apart from one whose label was merely pruned.
            unresolved: list = []
            _cand, reachable, _idx = _program_cfg(kids, unresolved=unresolved)
            reach_lines = {kids[i].line for i in reachable}
            if diagnostics is not None:
                for n, name in unresolved:
                    diagnostics.append(ParseDiagnostic(
                        file=file, start_line=n.line, end_line=n.line,
                        snippet=(f"{n.code.strip()!r} targets {name!r}, which no "
                                 "label defines; the edge was DROPPED, so any "
                                 "code reached only through it is missing"),
                    ))

        # Source node spans (line 1, col 0) .. end of the last real child.
        ends = [(n.end_point[0] + 1, n.end_point[1]) for n in real]
        end_line, end_column = max(ends)
        out.append(_node(1, 0, end_line, end_column, Source))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
