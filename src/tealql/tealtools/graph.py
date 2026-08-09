"""TEAL program graph: parse source into typed :mod:`.ast` nodes (one per opcode,
hashed by ``(file, line)``), then derive control-flow edges — each carrying a
``successor`` label — plus basic blocks from them via :mod:`.cfg.build`. SSA /
phis / const values are reconstructed downstream. The source may be a ``.teal``
file, a directory of them, or an in-memory ``{name: text}`` mapping.

Every edge here is a control-flow edge. Data dependencies live in a SEPARATE
graph (``ssa.render.data_graph``), and the taint graphs in :mod:`.dataflow` are
their own objects again — nothing merges them into this one.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import networkx as nx

from .ast import AstNode, Location


import base64
import hashlib
import re

# Pseudo-ops the tree-sitter grammar doesn't know: `byte` / `method` / `addr`
# parse as ERROR nodes and are DROPPED, starving their consumers, so they are
# rewritten line-for-line to the canonical push the assembler emits. `int` IS in
# the grammar and already const-resolves, so it is left untouched.


def _byte_literal(v: str):
    """Raw bytes for a TEAL byte literal (``0x`` / ``"str"`` / ``b64`` /
    ``base64(..)`` / ``b32`` / ``base32(..)``), or None if unrecognised.

    HAZARD: delegate to the one canonical decoder, never re-implement — a copy
    drifts: a per-character ``ord`` decoder turns the non-ASCII literal
    ``byte "caf\u00e9"`` into ``636166e9``, not the
    assembler's UTF-8 ``636166c3a9``, so every guard on it mis-evaluates."""
    from .ast.literals import decode_byte_literal
    try:
        raw, _kind = decode_byte_literal(v.strip())
    except Exception:
        return None
    return raw


def _strip_inline_comment(code: str) -> str:
    """Drop a ``//`` inline comment that sits outside a quoted string, outside a
    parenthesised group, and at a TOKEN BOUNDARY.

    HAZARD: all three rules are load-bearing, because the base64 alphabet
    includes ``/`` and a payload containing ``//`` is ordinary. Cutting at the
    first ``//`` truncates ``pushbytes base64(AA//)`` to ``base64(AA`` (the
    value silently becomes the ASCII of the fragment) and decodes
    ``pushbytes base64 AAAAAA//`` to four zero bytes — a guard against such a
    constant then never matches, and nothing reports it. The token-boundary rule
    is what go-algorand does: split on whitespace, then ask whether a token
    STARTS with ``//``, so ``int 1// x`` is not a comment at all."""
    def quote_is_escaped(index: int) -> bool:
        """A quote is escaped iff an odd run of backslashes precedes it.

        Looking only at the immediately preceding character mistakes the closing
        quote in ``"a\\\\"`` for an escaped quote: the first backslash escapes
        the second, so the quote actually terminates the literal.  Once quote
        state is wrong, a later quote-bearing comment is fed to tree-sitter as
        source and can turn an otherwise valid program into a partial parse.
        """
        backslashes = 0
        index -= 1
        while index >= 0 and code[index] == "\\":
            backslashes += 1
            index -= 1
        return backslashes % 2 == 1

    q = False
    depth = 0
    for i in range(len(code) - 1):
        c = code[i]
        if c == '"' and not quote_is_escaped(i):
            q = not q
        elif q:
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif (depth == 0 and code[i:i + 2] == "//"
                and (i == 0 or code[i - 1].isspace())):
            return code[:i]
    return code


#: a ``byte`` / ``method`` / ``addr`` pseudo-op at line start, any whitespace
#: after it (tab-separated forms count too).
_PSEUDO_OP_RE = re.compile(r"(?:^|\n)[ \t]*(?:byte|method|addr)[ \t]")

#: Real opcodes taking a byte-LITERAL operand list. The grammar takes ``0x..``
#: and ``"str"`` but NOT the ``base64(..)`` / ``b32(..)`` encodings the assembler
#: allows: the line parses as an ERROR and the opcode keeps EMPTY immediates, so
#: the constant is gone. For ``bytecblock`` — which is how Puya emits embedded
#: program bytes — that leaves every ``bytec_N`` in the program resolving to
#: nothing.
_BYTE_LITERAL_OPS = frozenset({"pushbytes", "pushbytess", "bytecblock"})

#: The encodings the grammar chokes on, in either spelling and either form.
_BYTE_ENC_RE = re.compile(r"\b(?:b64|base64|b32|base32)\s*[( ]")

#: Ops whose operand is a LABEL (a mangled label must be renamed there too).
#: Comparison is against the WHOLE first token, so the bare ``b`` branch here
#: never matches the separate ``b+`` / ``b-`` tokens.
_LABEL_REF_OPS = frozenset({"b", "bz", "bnz", "callsub", "match", "switch"})


def _sanitize_path_labels(text: str) -> str:
    """Mangle grammar-unsafe ``/`` and ``.`` inside LABELS to ``_``.

    The grammar's label token stops at the first ``/``, so a path-named label
    (puya-sol emits ``callsub /home/dev/Token.sol.transfer``) truncates, the
    rest parses as bare ``/`` division opcodes, and the subroutine is never
    resolved. The rename covers the definition AND every branch / callsub /
    match / switch reference, so it is bijective and the CFG is identical; it is
    char-for-char, so column spans stay valid. A rename that would collide with
    another label is dropped rather than merging two blocks."""
    rename: dict[str, str] = {}
    existing: set[str] = set()
    for line in text.split("\n"):
        body = _strip_inline_comment(line.strip()).rstrip()
        if body.endswith(":") and len(body) > 1:
            label = body[:-1].rstrip()
            existing.add(label)
            if "/" in label or "." in label:
                rename[label] = label.replace("/", "_").replace(".", "_")
    if not rename:
        return text
    # A collision — with another mangled label or an existing one — would MERGE
    # two blocks, corrupting the CFG worse than the truncation. Drop it.
    taken: dict[str, str] = {}
    for label, mangled in list(rename.items()):
        if mangled in taken or mangled in existing - {label}:
            rename.pop(label, None)
            rename.pop(taken.get(mangled, ""), None)
            continue
        taken[mangled] = label
    if not rename:
        return text
    # Longest-first, so a label that is a prefix of another (``Foo`` vs
    # ``Foo_after@3``) cannot be rewritten inside the longer one.
    ordered = sorted(rename.items(), key=lambda kv: len(kv[0]), reverse=True)

    out = []
    for line in text.split("\n"):
        body = _strip_inline_comment(line.strip()).rstrip()
        op = body.split(None, 1)[0] if body else ""
        if (body.endswith(":") or op in _LABEL_REF_OPS) and ("/" in line or "." in line):
            for old, new in ordered:
                line = line.replace(old, new)
        out.append(line)
    return "\n".join(out)


def _blank_quoted_comments(text: str) -> str:
    """Blank out an inline ``//`` comment that CONTAINS a quote character.

    The grammar's string tokenizer runs past the ``//`` when the comment holds a
    ``"``, so on `pushbytes "asa_"   // [name, "asa_"]` the comment text becomes
    PART OF THE CONSTANT — a guard against that value can never match, and only
    a stray `]` shows up as a diagnostic. Blanked, not deleted, so line lengths
    and therefore every column span are preserved exactly."""
    if '"' not in text:
        return text
    out = []
    for line in text.split("\n"):
        code = _strip_inline_comment(line)
        comment = line[len(code):]
        out.append(code + " " * len(comment) if '"' in comment else line)
    return "\n".join(out)


def _opcode_named_labels(text: str) -> str:
    """Rename LABELS whose name is an opcode mnemonic (``pop:`` / ``concat:`` /
    ``get:`` …), at the definition and every reference.

    The grammar reads ``pop:`` as the ``pop`` OPCODE plus a stray ``:``, so the
    label is never defined and every ``b``/``match``/``switch`` targeting it
    loses its CFG edge; Puya names router labels after ABI methods, and methods
    called ``get`` / ``pop`` / ``concat`` are ordinary. The rename is bijective
    (CFG unchanged) and token-wise, never a substring sweep: a label named ``b``
    on the line ``b b`` must rename the operand and leave the opcode alone. It
    does NOT preserve line length, which is safe because spans are computed
    against this normalized text and line NUMBERS don't move. A rename colliding
    with an existing label is dropped."""
    mnemonics = _opcode_mnemonics()
    defs: set = set()
    for line in text.split("\n"):
        body = _strip_inline_comment(line.strip()).rstrip()
        if body.endswith(":") and len(body) > 1:
            defs.add(body[:-1].rstrip())
    clashing = {d for d in defs if d in mnemonics}
    if not clashing:
        return text
    rename = {}
    for d in sorted(clashing):
        cand = f"{d}_label"
        while cand in defs or cand in rename.values():
            cand += "_"
        rename[d] = cand

    out = []
    for line in text.split("\n"):
        code = _strip_inline_comment(line)
        body = code.strip()
        if not body:
            out.append(line); continue
        indent = line[:len(line) - len(line.lstrip())]
        comment = line[len(code):]
        if body.endswith(":") and body[:-1].rstrip() in rename:
            out.append(f"{indent}{rename[body[:-1].rstrip()]}:{comment}")
            continue
        toks = body.split()
        if toks[0] in _LABEL_REF_OPS and len(toks) > 1:
            # Operands only — token-wise — so the opcode itself is never touched.
            toks = [toks[0]] + [rename.get(t, t) for t in toks[1:]]
            out.append(f"{indent}{' '.join(toks)}{comment}")
            continue
        out.append(line)
    return "\n".join(out)


def _opcode_mnemonics() -> frozenset:
    """Every opcode token the grammar recognises, so a label colliding with one
    can be spotted — derived from the AVM arity table, never re-listed."""
    from .avm import SIG, _FRAME_OVERRIDES
    return frozenset(SIG) | frozenset(_FRAME_OVERRIDES) | frozenset({
        "dig", "bury", "cover", "uncover", "popn", "dupn",
        "pushints", "pushbytess", "match", "switch", "proto",
    })


#: Source rewrites applied, IN ORDER, before the grammar sees the text; each
#: works around a construct tree-sitter-teal cannot parse and is a no-op
#: otherwise. Order is load-bearing: comments are neutralised first (a quote
#: inside one derails the string tokenizer), then labels are made parseable,
#: and only then does the per-line pseudo-op rewrite below run.
_SOURCE_REWRITES = (
    ("blank quote-bearing comments", _blank_quoted_comments),
    ("sanitize path labels",         _sanitize_path_labels),
    ("rename opcode-named labels",   _opcode_named_labels),
)


def _normalize_pseudo_ops(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    for _name, rewrite in _SOURCE_REWRITES:
        text = rewrite(text)
    if not _PSEUDO_OP_RE.search(text) and not _BYTE_ENC_RE.search(text):
        return text.encode("utf-8")                # fast path: nothing to rewrite
    out = []
    for line in text.split("\n"):
        body = line.strip()
        if not body or body.startswith("//") or body.endswith(":"):
            out.append(line); continue
        indent = line[:len(line) - len(line.lstrip())]
        parts = _strip_inline_comment(body).split(None, 1)
        op = parts[0]
        operand = parts[1].strip() if len(parts) > 1 else ""
        new = None
        if op == "byte":
            b = _byte_literal(operand)
            new = f"pushbytes 0x{b.hex()}" if b is not None else None
        elif op == "addr":
            try:                                   # 58-char base32 = 32B pubkey + 4B csum
                raw = base64.b32decode(operand.strip() + "=" * (-len(operand.strip()) % 8))
                # The pubkey is the 32-byte prefix (+4B checksum = 36). A shorter
                # decode would silently corrupt the constant — reject it and let
                # the parser handle the original line.
                new = f"pushbytes 0x{raw[:32].hex()}" if len(raw) >= 32 else None
            except Exception:
                new = None
        elif op in _BYTE_LITERAL_OPS and _BYTE_ENC_RE.search(operand):
            # Re-encode each operand to `0x..`, which the grammar DOES accept;
            # `tokenize_operands` keeps a `base64(..)` group (and, folded, the
            # `b64 <data>` pair) as ONE token, so the operand list survives.
            from .ast.literals import tokenize_operands
            try:
                toks = tokenize_operands(operand, fold_byte_keywords=True)
                raws = [_byte_literal(t) for t in toks]
                new = (f"{op} " + " ".join(f"0x{r.hex()}" for r in raws)
                       if toks and all(r is not None for r in raws) else None)
            except Exception:
                new = None                          # leave it for the diagnostic
        elif op == "method":
            sig = operand.strip()
            if sig.startswith('"') and sig.endswith('"'):
                sig = sig[1:-1]
            sel = hashlib.new("sha512_256", sig.encode()).digest()[:4]
            new = f"pushbytes 0x{sel.hex()}"
        out.append(f"{indent}{new}" if new is not None else line)
    return "\n".join(out).encode("utf-8")


def _resolve_source_files(source):
    """Yield ``(relpath, bytes)`` for each ``.teal`` under ``source`` — a file, a
    directory, or an in-memory ``{name: str | bytes}`` mapping (no filesystem) —
    normalized by :func:`_normalize_pseudo_ops` so the parser sees only canonical
    opcodes."""
    from .sources import ProgramSources
    yield from ProgramSources.load(
        source, normalize=_normalize_pseudo_ops
    ).normalized_bytes().items()


def _load_source_bytes(source) -> dict[str, bytes]:
    """Map reported source name -> normalized source bytes.

    Filesystem directories report paths relative to the target root, preserving
    the old basename for top-level files while keeping nested duplicate basenames
    distinct.  In-memory mappings retain their historical basename when it is
    unique; only an otherwise-colliding name expands to its supplied relative
    path.  This preserves existing editor integrations while no longer dropping
    one of two ``*/prog.teal`` entries.
    """
    from .sources import ProgramSources
    return ProgramSources.load(
        source, normalize=_normalize_pseudo_ops
    ).normalized_bytes()


def _slice_source(sources: dict[str, list[str]], loc: Location) -> str:
    """Source text covered by a :class:`Location` — lines 1-based, columns
    0-based half-open ``[start, end)``, ``""`` for a multi-line span."""
    lines = sources.get(loc.file) or sources.get(Path(loc.file).name)
    if lines is None:
        return ""
    if loc.start_line != loc.end_line:
        return ""
    if loc.start_line < 1 or loc.start_line > len(lines):
        return ""
    return lines[loc.start_line - 1][loc.start_column : loc.end_column]


def load_graph(
    source,
) -> nx.MultiDiGraph:
    """Build a MultiDiGraph from a ``.teal`` file, a directory of them, or an
    in-memory ``{name: str | bytes}`` mapping (no filesystem)."""
    if not isinstance(source, Mapping):
        source = Path(source).resolve()
        if not source.exists():
            raise FileNotFoundError(source)
    from .sources import ProgramSources
    sources = ProgramSources.load(source, normalize=_normalize_pseudo_ops)
    g_source = sources.label

    g = nx.MultiDiGraph()
    g.graph["source"] = g_source
    g.graph["sources"] = sources

    # (file, start_line) -> AstNode, for the const-value mapping below.
    by_loc: dict[tuple[str, int], AstNode] = {}

    # Pass 1: parse into AstNodes. Pass 2: derive CFG edges + BBs from them.
    from .ast.parse import parse_nodes
    from .cfg.build import build_cfg
    parse_diags: list = []
    nodes = parse_nodes(sources.normalized_bytes(), diagnostics=parse_diags)
    # HAZARD: spans the grammar dropped. Non-empty => the graph, and everything
    # built on it, covers only PART of the source; consumers surface this via
    # SSAProgram.parse_diagnostics.
    g.graph["parse_diagnostics"] = tuple(parse_diags)
    for node in nodes:
        by_loc[(node.location.file, node.location.start_line)] = node
        g.add_node(node)
    # One CFG walk for both products: it is the dominant cost of loading a
    # graph, and edges + blocks must agree on reachability anyway.
    cfg_edges, cfg_blocks = build_cfg(nodes)
    for u, v, t in cfg_edges:
        g.add_edge(u, v, successor=t)
    for node, bb_first, bb_last in cfg_blocks:
        g.nodes[node]["bb"] = (node.location.file, bb_first, bb_last)

    # Resolved literal constants per output: populates ``const_outputs``
    # ``{out_idx: (kind, value)}`` and the single-output scalar ``const_value``.
    from .const_values import compute_const_values
    for cf, cl, coi, ckind, cval in compute_const_values(g):
        node = by_loc.get((cf, int(cl)))
        if node is None:
            continue
        g.nodes[node].setdefault("const_outputs", {})[int(coi)] = (ckind, cval)
    for node in list(g.nodes):
        outs = g.nodes[node].get("const_outputs")
        if outs and len(outs) == 1 and 1 in outs:
            g.nodes[node]["const_value"] = outs[1]

    return g
