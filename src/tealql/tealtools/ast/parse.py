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
    ZeroArgumentOpcode, node_class_for_mnemonic,
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
    ``int`` opcode node; :mod:`const_values` resolves the name to its value.

    Deliberately ``int`` only, NOT ``pushint``. The named form the grammar
    rejects for ``int`` is an OnCompletion / TxnType constant, which
    ``const_values`` can resolve. The ``pushint`` case seen in the wild is
    ``pushint TMPL_DELETABLE`` — a deployment TEMPLATE, whose value is unknown
    until deploy time. Recovering it yields a push with no resolvable value,
    which the lift's lowering cannot express (``'PushintOpcode' is not a valid
    AVMOp``), so it stays a visible diagnostic rather than IR the lift chokes
    on."""
    return (
        c.type == "ERROR"
        and len(c.children) >= 2
        and c.children[0].type == "int"
        and c.children[1].type == "label_identifier"
    )

#: Every mnemonic that carries a FIELD-NAME immediate — the ops whose field
#: enumeration the grammar hard-codes, and therefore the ops a newer or simply
#: missed field name can break. The txn-family READS come from the AVM tables
#: (derived, not re-listed); the field WRITE and the params/holding queries are
#: added here because they take a field name too. ``itxn_field`` matters most:
#: it POPS, so dropping it loses the write AND leaves the stack one deep.
def _field_arg_mnemonics() -> frozenset:
    from ..avm import ITXN_SOURCE_OPS, TXN_SOURCE_OPS
    return TXN_SOURCE_OPS | ITXN_SOURCE_OPS | frozenset({
        "itxn_field",
        "app_params_get", "asset_params_get", "acct_params_get",
        "asset_holding_get", "voter_params_get", "block",
    })


_TXN_FIELD_MNEMONICS = _field_arg_mnemonics()


def _unknown_txn_field_error(c) -> bool:
    """A tree-sitter ERROR that is really a txn-family field read the grammar's
    field enumeration does not list — ``txn GroupID``, ``txn AssetCloseAmount``,
    ``txn RejectVersion`` (and the ``gtxn``/``itxn``/… forms of each).

    The grammar hard-codes the set of field names, so a field added by a newer
    AVM version — or simply missed — parses as an ERROR and the WHOLE
    instruction is dropped as an unparseable span. That is not a cosmetic loss:
    the push disappears, so the stack simulation every later analysis is built
    on is short one value from that point, and any consumer of the field (a
    ``log`` of ``txn GroupID``, an ``AssetCloseAmount`` guard) silently loses
    its operand.

    Recovering it needs no special emit path: the ERROR's first child IS the
    mnemonic token (``txn``), which is exactly what :func:`_class_for` keys on,
    and :func:`_loc` spans the whole node so ``.code`` carries the full
    ``txn GroupID`` text for the immediates. ``avm._TXN_FIELD_TYPE`` already
    types all three correctly, so only the parse was missing.

    Deliberately narrow: the node must start with a txn-family mnemonic and
    contain a bare identifier (the field name). Anything else stays an
    unparseable-span diagnostic. ERROR recovery is GREEDY, so two adjacent bad
    reads collapse into ONE node — :func:`_split_txn_field_error` segments them,
    exactly as the named-int path does."""
    if c.type != "ERROR" or len(c.children) < 2:
        return False
    if c.children[0].type not in _TXN_FIELD_MNEMONICS:
        return False
    return any(k.type == "label_identifier" for k in c.children[1:])


def _split_txn_field_error(c) -> "tuple[list, list]":
    """Segment a (possibly greedy) txn-field ERROR into ``(groups, unconsumed)``.

    Each group is ``[mnemonic, …immediates…, field_identifier]`` — one recovered
    instruction. Children that do not fit that shape are returned separately so
    the caller can report them rather than drop them in silence."""
    groups: list = []
    unconsumed: list = []
    kids = [k for k in c.children if not _is_trivia(k.type)]
    i = 0
    while i < len(kids):
        if kids[i].type not in _TXN_FIELD_MNEMONICS:
            unconsumed.append(kids[i])
            i += 1
            continue
        j = i + 1
        while j < len(kids) and kids[j].type == "numeric_argument":
            j += 1                                   # immediate group/array index
        if j < len(kids) and kids[j].type == "label_identifier":
            groups.append(kids[i:j + 1])
            i = j + 1
        else:
            unconsumed.extend(kids[i:j + 1])         # mnemonic with no field
            i = j + 1
    return groups, unconsumed


#: Opcode nodes whose trailing NUMERIC immediate the grammar drops into a bare
#: ERROR. ``itxna`` loses its array index; ``gaid`` loses its group index
#: entirely (the grammar rejects EVERY index, not just an out-of-range one, and
#: types the op as a zero-argument opcode).
_INDEX_TAIL_NODES = frozenset({"itxna_opcode", "zero_argument_opcode"})
_INDEX_TAIL_MNEMONICS = frozenset({"itxna", "gaid"})


def _itxna_index_split(ch, nxt, src: bytes) -> bool:
    """The grammar's ``itxna`` rule takes only a FIELD, no array index — so
    ``itxna Logs 1`` parses as an ``itxna_opcode`` covering ``itxna Logs`` plus
    a bare ERROR holding the ``1``. ``gaid N`` is the same defect with the
    index gone completely: the op types as a ZERO-argument opcode and the
    index becomes a bare ERROR, so ``gaid 5`` and ``gaid 20`` — different
    group transactions — are indistinguishable.

    The opcode SURVIVES, which is what makes this nastier than a clean drop:
    its ``.code`` is ``itxna Logs``, so the immediates lose the index entirely
    and ``itxna Logs 0`` becomes indistinguishable from ``itxna Logs 5``. Every
    analysis keyed on the array slot — input unification's canonical key, the
    taint layer's per-slot identity — then conflates distinct elements of the
    SAME array, silently. (``txna`` has the ``numeric_argument`` child and is
    fine; ``gitxna`` is fine; it is specifically ``itxna``.)

    Re-span the opcode through the index tail, exactly as
    :func:`_hex_int_split` does for a split numeric literal. Same line only, so
    an unrelated ERROR below can never be absorbed."""
    if ch.type not in _INDEX_TAIL_NODES or nxt is None or nxt.type != "ERROR":
        return False
    mnem = ch.children[0].type if ch.children else None
    if mnem not in _INDEX_TAIL_MNEMONICS:
        return False
    if ch.end_point[0] != nxt.start_point[0]:
        return False                               # different lines
    tail = src[nxt.start_byte:nxt.end_byte].decode("utf-8", "replace").strip()
    return tail.isdigit()


#: Opcodes whose operand list may carry a deployment TEMPLATE VARIABLE.
_TEMPLATE_HOST_NODES = frozenset({
    "intcblock_opcode", "bytecblock_opcode",
    "pushints_opcode", "pushbytess_opcode",
})
#: NOT the single-push opcodes. A CONST BLOCK holding a template keeps its
#: other slots useful and its arity right, so recovering it is a clear win. A
#: bare `pushint TMPL_DELETABLE` recovers to a push with no resolvable value,
#: which the lift's lowering cannot express (`'PushintOpcode' is not a valid
#: AVMOp` on the xgov contract) — so it stays a visible diagnostic instead.

#: A deployment template variable: an ALL-CAPS ``PREFIX_NAME`` identifier.
#: ``TMPL_`` is the algokit default, but puya lets a contract choose its own
#: (the ``compile_HelloPrfx`` fixture uses ``PRFX_``), so keying on the literal
#: ``TMPL_`` missed real ones. Still narrow enough that an ordinary
#: lowercase identifier after a const block is not mistaken for a template.
_TEMPLATE_VAR_RE = __import__("re").compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")


def _is_phantom_label(c) -> bool:
    """A ``label`` node tree-sitter SALVAGED from a bare identifier, rather than
    a real ``name:`` definition.

    A stray identifier — the tail of a truncated operand list, a typo — parses
    as a ``label`` whose ``:`` token tree-sitter had to INVENT, and an invented
    token is flagged ``is_missing``. A real ``main:`` has a genuine ``:``.

    Without this, such an identifier was swallowed in total silence: no label
    (reachability-gating drops it), no diagnostic, and the operand list it came
    from quietly truncated. `bytecblock "a" somethingelse` reported nothing at
    all while dropping a token."""
    if c.type != "label":
        return False
    return any(k.type == ":" and k.is_missing for k in c.children)


def _phantom_is_opcode(c, src: bytes) -> bool:
    """A phantom label whose identifier is a KNOWN opcode mnemonic — i.e. an
    opcode the grammar does not model, salvaged as a bare identifier."""
    from ..avm import SIG
    text = src[c.start_byte:c.end_byte].decode("utf-8", "replace").strip()
    return text in SIG


def _template_var_tail(ch, nxt, src: bytes) -> bool:
    """A const block whose operand list ends in un-instantiated deployment
    TEMPLATE VARIABLES (``bytecblock "greeting" TMPL_GREETING``,
    ``intcblock 1 64 TMPL_DELETABLE``).

    The grammar has no template-variable token, so the opcode node STOPS at the
    last real literal and the ``TMPL_*`` tail becomes a separate node — an
    ERROR, or (worse) a spurious ``label`` DEFINITION, since `TMPL_X` on its own
    looks exactly like one. A phantom label is a phantom branch target.

    Re-spanning the opcode through the tail keeps the block's ARITY right, which
    is what actually matters: ``bytec_N`` indexes the block POSITIONALLY, so a
    truncated list silently renumbers every later slot. The template slots
    themselves stay UNRESOLVED — a template's value is genuinely unknown until
    deployment — which :mod:`const_values` models per slot."""
    if ch.type not in _TEMPLATE_HOST_NODES or nxt is None:
        return False
    if nxt.type not in ("ERROR", "label"):
        return False
    if ch.end_point[0] != nxt.start_point[0]:
        return False
    kids = [k for k in nxt.children if k.type == "label_identifier"]
    if not kids:
        return False
    return all(_TEMPLATE_VAR_RE.match(
        src[k.start_byte:k.end_byte].decode("utf-8", "replace")) for k in kids)


_NUMERIC_ARG_OPCODES = frozenset({
    "single_numeric_argument_opcode",   # int / pushint
    "intcblock_opcode",
    "intc_opcode",
    "pushints_opcode",
})


def _hex_int_split(ch, nxt, src: bytes) -> bool:
    """A grammar hex/oct/bin-literal split: ``ch`` is a decimal-numeric int opcode
    whose literal was truncated at the ``0`` (the ``numeric_argument`` rule accepts
    only decimal), and ``nxt`` is the adjacent ``x..`` / ``o..`` / ``b..`` tail the
    grammar mis-emitted as a ``label`` / ``ERROR``. Adjacency (``nxt`` starts
    exactly where ``ch`` ends, no whitespace) is unambiguous: a label / stray token
    fused to an opcode's operand is never valid TEAL, so this only ever fires on a
    split literal. Over-merging a genuinely malformed token degrades to ``None`` in
    ``const_values`` (never a wrong value)."""
    if ch.type not in _NUMERIC_ARG_OPCODES or nxt.type not in ("label", "ERROR"):
        return False
    if nxt.start_byte != ch.end_byte:            # must be adjacent — no whitespace
        return False
    return src[nxt.start_byte:nxt.start_byte + 1] in (b"x", b"X", b"o", b"O",
                                                      b"b", b"B")


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
            if (_named_int_error(c) or _unknown_txn_field_error(c)
                    or (real and c.type in ("ERROR", "label")
                        and (_itxna_index_split(real[-1], c, src)
                             or _template_var_tail(real[-1], c, src)))):
                real.append(c)
            elif c.type == "ERROR" and real and _hex_int_split(real[-1], c, src):
                # a hex/oct/bin int tail the grammar split off (e.g. the `x10 5`
                # after `intcblock 0`) — keep it so the next pass merges it back,
                # rather than dropping it as an unparseable-span diagnostic.
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
        i = 0
        while i < len(real):
            ch = real[i]
            nxt = real[i + 1] if i + 1 < len(real) else None
            if nxt is not None and (_hex_int_split(ch, nxt, src)
                                    or _itxna_index_split(ch, nxt, src)
                                    or _template_var_tail(ch, nxt, src)):
                # Recovered `int 0x10` / `pushint 0x..` / `intcblock 0x.. ..`: the
                # grammar's numeric_argument is DECIMAL-only, so a hex/oct/bin
                # literal parses as `<op> 0` plus an adjacent bogus `label`/`ERROR`
                # tail (`x10`). Re-span the opcode through that tail so its `.code`
                # carries the whole literal; const_values then resolves it.
                cls, override = _class_for(ch)
                op_nodes.append(_node(
                    ch.start_point[0] + 1, ch.start_point[1],
                    nxt.end_point[0] + 1, nxt.end_point[1],
                    cls, override))
                i += 2
                continue
            if _unknown_txn_field_error(ch):
                # Recovered txn-family field read the grammar's field list is
                # missing (`txn GroupID` / `AssetCloseAmount` / `RejectVersion`).
                # `_class_for` keys on the ERROR's first child — the mnemonic
                # token — so each group emits as the very node the grammar would
                # have produced for a known field.
                groups, unconsumed = _split_txn_field_error(ch)
                for grp in groups:
                    cls, override = _class_for(ch)
                    op_nodes.append(_node(
                        grp[0].start_point[0] + 1, grp[0].start_point[1],
                        grp[-1].end_point[0] + 1, grp[-1].end_point[1],
                        cls, override))
                if unconsumed and diagnostics is not None:
                    lo = min(u.start_point[0] for u in unconsumed) + 1
                    hi = max(u.end_point[0] for u in unconsumed) + 1
                    text = src[unconsumed[0].start_byte:
                               unconsumed[-1].end_byte].decode("utf-8", "replace")
                    snippet = (text.splitlines()[0].strip()[:80]
                               if text.strip() else "")
                    diagnostics.append(ParseDiagnostic(
                        file=file, start_line=lo, end_line=hi, snippet=snippet,
                    ))
                i += 1
                continue
            if _named_int_error(ch):
                # Recovered `int <name>`: span each `int` token through its named
                # identifier (tight, robust to greedy ERROR recovery), emit as
                # the same opcode class a numeric `int N` gets.
                #
                # ERROR recovery is GREEDY: consecutive named ints
                # (`int pay` / `int axfer`) collapse into ONE error node, so
                # recovering only children[0..1] silently swallowed every
                # instruction after the first. Walk the whole child list,
                # recovering every `int <name>` pair, and record anything left
                # unconsumed as a diagnostic rather than dropping it in silence.
                kids_e = list(ch.children)
                j = 0
                unconsumed: list = []
                while j < len(kids_e):
                    a = kids_e[j]
                    b = kids_e[j + 1] if j + 1 < len(kids_e) else None
                    if (a.type == "int" and b is not None
                            and b.type == "label_identifier"):
                        op_nodes.append(_node(
                            a.start_point[0] + 1, a.start_point[1],
                            b.end_point[0] + 1, b.end_point[1],
                            SingleNumericArgumentOpcode))
                        j += 2
                        continue
                    if not _is_trivia(a.type):
                        unconsumed.append(a)
                    j += 1
                if unconsumed and diagnostics is not None:
                    lo = min(u.start_point[0] for u in unconsumed) + 1
                    hi = max(u.end_point[0] for u in unconsumed) + 1
                    text = src[unconsumed[0].start_byte:
                               unconsumed[-1].end_byte].decode("utf-8", "replace")
                    snippet = (text.splitlines()[0].strip()[:80]
                               if text.strip() else "")
                    diagnostics.append(ParseDiagnostic(
                        file=file, start_line=lo, end_line=hi, snippet=snippet,
                    ))
                i += 1
                continue
            sl, sc, el, ec = _loc(ch)
            if _is_phantom_label(ch) and _phantom_is_opcode(ch, src):
                # An opcode the grammar has never heard of (a newer AVM
                # version's) parses as a bare identifier and would be DROPPED —
                # taking its whole stack effect with it. `falcon_verify` (AVM
                # 12, 3 in / 1 out) vanished exactly this way, desyncing the
                # simulation from that point on. `avm.SIG` already knows its
                # arity; emit it as the opcode it is.
                mnem = src[ch.start_byte:ch.end_byte].decode(
                    "utf-8", "replace").strip()
                cls = node_class_for_mnemonic(mnem) or ZeroArgumentOpcode
                op_nodes.append(_node(sl, sc, el, ec, cls,
                                      None if cls is not ZeroArgumentOpcode
                                      else _ts_to_pascal(f"{mnem}_opcode")))
            elif _is_phantom_label(ch):
                # Not a label: a bare identifier tree-sitter salvaged (see
                # _is_phantom_label). Record the drop rather than swallow it.
                if diagnostics is not None:
                    text = src[ch.start_byte:ch.end_byte].decode("utf-8", "replace")
                    diagnostics.append(ParseDiagnostic(
                        file=file, start_line=sl, end_line=el,
                        snippet=(f"stray token {text.strip()!r} is not a label and "
                                 "was DROPPED (an operand list may be truncated)"),
                    ))
            elif ch.type == "label":
                label_nodes.append(_node(sl, sc, el, ec, Label))
            else:
                cls, override = _class_for(ch)
                op_nodes.append(_node(sl, sc, el, ec, cls, override))
            i += 1

        # One instruction per line is an ARCHITECTURAL invariant, not a style
        # preference: AstNode identity, SSAVar identity (file, line, index),
        # the scratch/cost/graph indexes and every reported violation are all
        # keyed by (file, line). TEAL's grammar does allow `int 1; int 2`, and
        # such a line silently COLLAPSES to a single graph node — the extra
        # pushes vanish and the consuming op loses operands. We cannot
        # represent it, so we must not pretend to: record it through the same
        # channel as unparseable source (strict callers then refuse, and a
        # scan of such a file never reads as "clean").
        if diagnostics is not None:
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
            # Duplicate labels: the assembler rejects them, and branch
            # resolution can only pick one target, so the other definition's
            # code becomes unreachable and is pruned. Never silently.
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
            _cand, reachable, _idx = _program_cfg(kids)
            reach_lines = {kids[i].line for i in reachable}

        # Source node: the whole program, (line 1, col 0) .. the end of the
        # last real child (native half-open columns).
        last = real[-1]
        out.append(_node(1, 0, last.end_point[0] + 1, last.end_point[1], Source))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
