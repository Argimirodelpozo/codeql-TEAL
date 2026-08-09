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
from .ast import (
    AstNode, Label, Location, SingleNumericArgumentOpcode, Source,
    ZeroArgumentOpcode, node_class_for_mnemonic,
)
from .literals import is_template_variable

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


def _neutralise_comment_continuations(src: bytes) -> bytes:
    r"""Stop a comment that ends in ``\`` from swallowing the next line.

    A TEAL comment runs to END OF LINE -- the AVM has no line-continuation. The
    tree-sitter-teal grammar disagrees: it lets a trailing backslash continue a
    ``comment`` node onto the following line, so the instruction there is parsed as
    comment text and vanishes from the node stream entirely. Nothing downstream can
    see it: ``comment`` is trivia, so no ERROR is raised and no diagnostic fires --
    the block simply loses a stack push and every later stack reference in it shifts
    by one slot. Real damage, silently: puya writes the contract's own Python source
    into comments, and a Python line-continuation ends in exactly that backslash, so

        // self.buckets[id].capacity = bucket.limit \
        bytec_3                                       <-- swallowed

    lifted with `bytec_3` missing, and the block's later `uncover 3` then read a
    frame slot instead of the pushed key (seen in Folks Finance's Wormhole NTT
    NttManager, where it mistyped a `box_replace` value operand).

    The backslash is overwritten with a SPACE rather than deleted: same byte length,
    so every offset, line and column downstream stays exactly as the source had it.
    Only bytes inside a comment are ever touched.
    """
    if b"\\" not in src:
        return src
    out = bytearray(src)
    n = len(out)
    i = 0
    while i < n:
        eol = out.find(b"\n", i)
        if eol == -1:
            eol = n
        # find this line's comment start: the first `//` that is not inside a
        # double-quoted byte literal (`pushbytes "http://x"` is not a comment).
        cstart, in_str, esc, k = -1, False, False, i
        while k < eol:
            ch = out[k]
            if in_str:
                if esc:
                    esc = False
                elif ch == 0x5C:            # backslash
                    esc = True
                elif ch == 0x22:            # closing quote
                    in_str = False
            elif ch == 0x22:                # opening quote
                in_str = True
            elif ch == 0x2F and k + 1 < eol and out[k + 1] == 0x2F:
                cstart = k
                break
            k += 1
        if cstart >= 0:
            end = eol - 1 if eol > i and out[eol - 1] == 0x0D else eol
            if end - 1 > cstart and out[end - 1] == 0x5C:
                out[end - 1] = 0x20
        i = eol + 1
    return bytes(out)


def _rewrite_scoped_label_separators(src: bytes) -> bytes:
    """Make a scoped subroutine label parseable: ``a::b`` -> ``a__b``.

    puya-ts names subroutines after the source that produced them --
    ``callsub smart_contracts/main/contract.algo.ts::Main.cardAssetOptIn`` -- and the grammar's
    label rule stops at the first ``:``, since that is what TERMINATES a label definition. The
    ``::`` and everything after it becomes an unparsed span, so the subroutine drops out of the
    analysis entirely: on auto-draw-card's Main that is 5 spans, silently removed.

    Renaming is safe where blanking would not be, because a label is only a NAME: the definition
    and every ``callsub``/``b`` referencing it are rewritten by the same rule, so they still agree.
    Two bytes for two, so offsets, lines and columns are unchanged. Quoted byte literals are
    skipped -- ``pushbytes "a::b"`` is DATA, and rewriting it would corrupt the program rather than
    rename part of it.
    """
    if b"::" not in src:
        return src
    out = bytearray(src)
    i, n = 0, len(out)
    while i < n:
        eol = out.find(b"\n", i)
        if eol == -1:
            eol = n
        in_str, esc, k = False, False, i
        while k < eol - 1:
            ch = out[k]
            if in_str:
                if esc:
                    esc = False
                elif ch == 0x5C:
                    esc = True
                elif ch == 0x22:
                    in_str = False
            elif ch == 0x22:
                in_str = True
            elif ch == 0x3A and out[k + 1] == 0x3A:      # `::` outside a literal
                out[k] = out[k + 1] = 0x5F              # -> `__`
                k += 1
            k += 1
        i = eol + 1
    return bytes(out)


def _named_int_error(c, src: bytes = b"") -> bool:
    """A tree-sitter ERROR that is really the ``int <NamedConstant>`` pseudo-op.

    GRAMMAR DEFECT: ``int`` accepts only a numeric argument, so the named
    OnCompletion / TxnType form (``int DeleteApplication``, ``int pay``) parses
    as ERROR; dropping it loses the push, so its consumer loses an operand.
    Recovered as an ``int`` node — :mod:`const_values` resolves the name.

    HAZARD: ``int`` only, never ``pushint``. The wild ``pushint`` named form is
    ``pushint TMPL_X``, a deploy-time TEMPLATE with no resolvable value;
    recovering it yields IR the lift cannot lower, so it stays a diagnostic."""
    return (
        c.type == "ERROR"
        and len(c.children) >= 2
        and c.children[0].type == "int"
        and c.children[1].type == "label_identifier"
    )

#: Every mnemonic carrying a FIELD-NAME immediate — i.e. every op the grammar's
#: hard-coded field enumeration can break. txn-family reads are derived from the
#: AVM tables; the field WRITE and params/holding queries are added here.
#: ``itxn_field`` matters most: it POPS, so dropping it loses the write AND
#: leaves the stack one deep.
def _field_arg_mnemonics() -> frozenset:
    from ..language.avm import ITXN_SOURCE_OPS, TXN_SOURCE_OPS
    return TXN_SOURCE_OPS | ITXN_SOURCE_OPS | frozenset({
        "itxn_field",
        "app_params_get", "asset_params_get", "acct_params_get",
        "asset_holding_get", "voter_params_get", "block",
    })


_TXN_FIELD_MNEMONICS = _field_arg_mnemonics()


def _unknown_txn_field_error(c, src: bytes = b"") -> bool:
    """A tree-sitter ERROR that is really a txn-family read of a field the
    grammar's enumeration omits (``txn GroupID`` / ``AssetCloseAmount`` /
    ``RejectVersion``, and the ``gtxn``/``itxn``/… forms of each).

    GRAMMAR DEFECT: the field-name set is hard-coded, so a newer or missed field
    parses as ERROR and the WHOLE instruction is dropped — the push disappears
    and the stack simulation is short one value from there on.

    Deliberately narrow: a txn-family mnemonic plus a bare identifier; anything
    else stays a diagnostic. ERROR recovery is GREEDY, so two adjacent bad reads
    collapse into ONE node — :func:`_split_txn_field_error` segments them."""
    if c.type != "ERROR" or len(c.children) < 2:
        return False
    if c.children[0].type not in _TXN_FIELD_MNEMONICS:
        return False
    return any(k.type == "label_identifier" for k in c.children[1:])


def _split_txn_field_error(c) -> "tuple[list, list]":
    """Segment a greedy txn-field ERROR into ``(groups, unconsumed)``, each group
    ``[mnemonic, …immediates…, field_identifier]`` — one recovered instruction;
    children that do not fit come back separately so the caller reports them."""
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
#: ERROR: ``itxna`` loses its array index, ``gaid`` its group index (every
#: index, not just out-of-range ones; the op then types as zero-argument).
_INDEX_TAIL_NODES = frozenset({"itxna_opcode", "zero_argument_opcode"})
_INDEX_TAIL_MNEMONICS = frozenset({"itxna", "gaid"})


def _itxna_index_split(ch, nxt, src: bytes) -> bool:
    """An opcode node followed by the bare-ERROR numeric index the grammar split
    off it, to be merged back by re-spanning.

    GRAMMAR DEFECT: ``itxna`` takes only a FIELD, so ``itxna Logs 1`` parses as
    ``itxna Logs`` plus an ERROR holding the ``1``; ``gaid N`` loses its index
    the same way and types as a ZERO-argument opcode. (``txna`` and ``gitxna``
    are fine — they have the ``numeric_argument`` child.)

    HAZARD: the opcode SURVIVES with its index gone, so ``itxna Logs 0`` and
    ``itxna Logs 5`` become identical and every slot-keyed analysis (input
    unification, per-slot taint) silently conflates distinct array elements.

    Same line only, so an unrelated ERROR below can never be absorbed."""
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
    "single_numeric_argument_opcode", "pushbytes_opcode",
})
#: NOT the single-push opcodes: a const BLOCK holding a template keeps its other
#: slots and its arity, but a bare `pushint TMPL_X` recovers to a push with no
#: resolvable value, which the lift cannot lower — it stays a diagnostic.




def _is_phantom_label(c) -> bool:
    """A ``label`` node tree-sitter SALVAGED from a bare identifier (a truncated
    operand list's tail, a typo) rather than a real ``name:`` definition.

    Detected by the ``:`` token being ``is_missing`` — tree-sitter had to invent
    it, whereas a real ``main:`` has a genuine one. Untreated, such a token is
    swallowed in total silence: no label, no diagnostic, operand list truncated."""
    if c.type != "label":
        return False
    return any(k.type == ":" and k.is_missing for k in c.children)


#: Const-push mnemonics that can carry a template variable as their operand.
_TEMPLATE_PUSH_MNEMONICS = frozenset({"pushint", "pushbytes", "int", "byte"})


def _template_push_error(c, src: bytes) -> bool:
    """``ERROR[<push mnemonic>, <TEMPLATE identifier>]`` — the BARE form.

    GRAMMAR DEFECT: `pushint TMPL_X // comment` parses as an opcode plus a
    salvaged tail (:func:`_template_var_tail`), but WITHOUT the trailing comment
    the same line parses as one ERROR that CONTAINS the mnemonic. Two shapes for
    one construct; miss this one and the push is dropped, leaving the stack
    short."""
    if c.type != "ERROR" or len(c.children) < 2:
        return False
    if c.children[0].type not in _TEMPLATE_PUSH_MNEMONICS:
        return False
    rest = [k for k in c.children[1:] if not _is_trivia(k.type)]
    return bool(rest) and all(
        k.type == "label_identifier"
        and is_template_variable(
            src[k.start_byte:k.end_byte].decode("utf-8", "replace"))
        for k in rest)


def _end_of_line(node, src: bytes) -> "tuple[int, int]":
    """``(line, end_col)`` of the end of the line ``node`` STARTS on — clamps a
    re-spanned opcode so it never runs past its own line."""
    row = node.start_point[0]
    lines = src.decode("utf-8", "replace").split("\n")
    return row + 1, len(lines[row]) if row < len(lines) else node.end_point[1]


def _phantom_is_opcode(c, src: bytes) -> bool:
    """A phantom label whose identifier is a KNOWN opcode mnemonic — an opcode the
    grammar does not model, salvaged as a bare identifier."""
    from ..language.avm import SIG
    text = src[c.start_byte:c.end_byte].decode("utf-8", "replace").strip()
    return text in SIG


def _template_var_tail(ch, nxt, src: bytes) -> bool:
    """A const block whose operand list ends in un-instantiated deployment
    TEMPLATE VARIABLES (``bytecblock "greeting" TMPL_GREETING``).

    GRAMMAR DEFECT: there is no template-variable token, so the opcode STOPS at
    the last real literal and the ``TMPL_*`` tail becomes an ERROR — or, worse,
    a spurious ``label`` DEFINITION, i.e. a phantom branch target.

    HAZARD: re-spanning through the tail is about ARITY. ``bytec_N`` indexes the
    block POSITIONALLY, so a truncated list silently renumbers every later slot.
    The template slots stay unresolved (:mod:`const_values` models them per
    slot) — their value is genuinely unknown until deployment."""
    if ch.type not in _TEMPLATE_HOST_NODES or nxt is None:
        return False
    if nxt.type not in ("ERROR", "label"):
        return False
    if ch.end_point[0] != nxt.start_point[0]:
        return False
    kids = [k for k in nxt.children if k.type == "label_identifier"]
    if not kids:
        return False
    return all(is_template_variable(
        src[k.start_byte:k.end_byte].decode("utf-8", "replace")) for k in kids)


_NUMERIC_ARG_OPCODES = frozenset({
    "single_numeric_argument_opcode",   # int / pushint
    "intcblock_opcode",
    "intc_opcode",
    "pushints_opcode",
})


def _hex_int_split(ch, nxt, src: bytes) -> bool:
    """An int opcode plus the ``x..``/``o..``/``b..`` tail of its split literal.

    GRAMMAR DEFECT: ``numeric_argument`` is DECIMAL-only, so ``int 0x10``
    truncates at the ``0`` and the tail mis-emits as a ``label``/``ERROR``.
    Adjacency (no whitespace between them) is unambiguous — a token fused to an
    operand is never valid TEAL — and over-merging degrades to ``None`` in
    ``const_values``, never to a wrong value."""
    if ch.type not in _NUMERIC_ARG_OPCODES or nxt.type not in ("label", "ERROR"):
        return False
    if nxt.start_byte != ch.end_byte:            # must be adjacent — no whitespace
        return False
    return src[nxt.start_byte:nxt.start_byte + 1] in (b"x", b"X", b"o", b"O",
                                                      b"b", b"B")


#: RECOVERY REGISTRIES — the list of valid TEAL the grammar rejects. Each gap is
#: recovered in one of two shapes: STANDALONE, an ERROR node that IS one or more
#: instructions, emitted on its own (`_class_for` keys on its first child, the
#: mnemonic token); or TAIL, a node belonging to the PRECEDING opcode, merged in
#: by re-spanning (always clamped to that opcode's own line). The next AVM
#: version's gap is one entry in one tuple.
_STANDALONE_RECOVERIES = (
    _named_int_error,            # `int DeleteApplication`
    _unknown_txn_field_error,    # `txn GroupID`, `itxn_field RejectVersion`
    _template_push_error,        # `pushint TMPL_DELETABLE`
)

_TAIL_RECOVERIES = (
    _hex_int_split,              # `int 0x10` split into `int 0` + `x10`
    _itxna_index_split,          # `itxna Logs 1` / `gaid 5` losing the index
    _template_var_tail,          # `bytecblock "a" TMPL_X`
)


def _is_standalone_recovery(c, src: bytes) -> bool:
    return any(f(c, src) for f in _STANDALONE_RECOVERIES)


def _is_tail_recovery(prev, node, src: bytes) -> bool:
    return prev is not None and any(f(prev, node, src) for f in _TAIL_RECOVERIES)


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
    appends a :class:`tealql.tealtools.core.errors.ParseDiagnostic` to ``diagnostics``
    when one is passed — the ONLY way a caller can tell a fully-parsed program
    from a partial one."""
    from ..core.errors import ParseDiagnostic
    from ..frontend.graph import _slice_source        # lazy: graph imports this module
    out: list = []
    for file, src in sources.items():
        if isinstance(src, str):
            src = src.encode("utf-8")
        src = _neutralise_comment_continuations(src)
        src = _rewrite_scoped_label_separators(src)
        root = _parser().parse(src).root_node

        real: list = []
        for c in root.children:
            if (_is_standalone_recovery(c, src)
                    or (c.type in ("ERROR", "label") and real
                        and _is_tail_recovery(real[-1], c, src))):
                real.append(c)
            elif c.type == "ERROR" and real and _hex_int_split(real[-1], c, src):
                # Keep the split hex/oct/bin tail so the next pass merges it back.
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
            if nxt is not None and _is_tail_recovery(ch, nxt, src):
                # Re-span the opcode through its salvaged tail so `.code` carries
                # the whole instruction, CLAMPED to the opcode's own line: a tail
                # can span further (swallowing a comment and the next line), and a
                # multi-line span slices to an EMPTY `.code`, whereupon `_opname`
                # falls back to `node_class` and the op becomes "PushintOpcode".
                el_, ec_ = _end_of_line(nxt, src)
                cls, override = _class_for(ch)
                op_nodes.append(_node(
                    ch.start_point[0] + 1, ch.start_point[1], el_, ec_,
                    cls, override))
                # Absorb EVERY tail starting on this line, not just the first: a
                # long operand list sheds more than one, and a leftover becomes
                # its own phantom label. Safe — the span is already clamped and
                # one instruction per line is architectural.
                i += 2
                while (i < len(real)
                       and real[i].start_point[0] == ch.start_point[0]):
                    i += 1
                continue
            if _unknown_txn_field_error(ch, src):
                # `_class_for` keys on the ERROR's first child — the mnemonic —
                # so each group emits as the node a known field would have got.
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
            if _named_int_error(ch, src):
                # ERROR recovery is GREEDY — consecutive named ints collapse into
                # ONE error node — so walk the whole child list, spanning each
                # `int` through its identifier, and report the leftovers.
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
                # GRAMMAR DEFECT: an opcode the grammar has never heard of (a
                # newer AVM version's, e.g. `falcon_verify`) parses as a bare
                # identifier and would be DROPPED, taking its stack effect with
                # it and desyncing the simulation. `avm.SIG` knows its arity.
                mnem = src[ch.start_byte:ch.end_byte].decode(
                    "utf-8", "replace").strip()
                cls = node_class_for_mnemonic(mnem) or ZeroArgumentOpcode
                op_nodes.append(_node(sl, sc, el, ec, cls,
                                      None if cls is not ZeroArgumentOpcode
                                      else _ts_to_pascal(f"{mnem}_opcode")))
            elif _is_phantom_label(ch):
                # A salvaged bare identifier, not a label — record the drop.
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

        # HAZARD: one instruction per line is ARCHITECTURAL, not stylistic —
        # AstNode identity, SSAVar identity (file, line, index), the
        # scratch/cost/graph indexes and every violation are keyed by
        # (file, line). TEAL allows `int 1; int 2`, which COLLAPSES to a single
        # node (extra pushes vanish, the consumer loses operands). We cannot
        # represent it, so it is reported like unparseable source.
        if diagnostics is not None:
            # The mirror image of the same architectural rule: a node whose span
            # COVERS later lines has swallowed them. `match` / `switch` with no
            # target list absorbs the next instruction as its operand, and that
            # instruction then exists for nothing downstream. No valid program
            # produces a multi-line span (0 across 1166 real programs), so this
            # only ever fires on the mangled case.
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
        last = real[-1]
        out.append(_node(1, 0, last.end_point[0] + 1, last.end_point[1], Source))
        out.extend(op_nodes)
        out.extend(n for n in label_nodes if n.location.start_line in reach_lines)
    return out
