"""TEAL program graph.

Build a NetworkX MultiDiGraph from TEAL source in two passes: parse the source
into typed :class:`tealql.tealtools.ast.AstNode` nodes (one per opcode, hashed by
``(file, line)``) via :mod:`tealql.tealtools.ast.parse`, then derive the control flow --
``kind="cfg"`` edges carrying a ``successor`` label, plus basic blocks -- from
those nodes via :mod:`tealql.tealtools.cfg_build`. SSA / phis / const values / taint
are reconstructed downstream (``tealql.tealtools.ssa``).

The source may be a single ``.teal`` file, a directory of ``.teal`` files, or an
in-memory ``{name: text}`` mapping.

Quick start
-----------
    >>> from tealql.tealtools.graph import load_graph
    >>> from .ast import Opcode, IntegerAddOpcode
    >>> g = load_graph("contract.teal")         # a .teal file or a dir of them
    >>> [n for n in g if isinstance(n, IntegerAddOpcode)]

Graphviz rendering of the loaded graph lives in :mod:`tealql.tealtools.viz`
(``to_dot`` / ``draw_cfg`` / ``cfg_bb_graph`` / ``draw_cfg_bb``).
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import networkx as nx

from .ast import AstNode, Location


import base64
import hashlib
import re

# TEAL assembler pseudo-ops the tree-sitter grammar doesn't know (`byte` / `method`
# / `addr` parse as ERROR nodes and get dropped, starving their consumers). Rewrite
# them line-for-line to the canonical push the assembler itself emits, so the whole
# pipeline sees real opcodes. `int` IS in the grammar (single_numeric_argument) and
# already const-resolves, so it's left untouched. Canonical (disassembled) sources
# have none of these -> unchanged.


def _byte_literal(v: str):
    """Raw bytes for a TEAL byte literal (``0x`` / ``"str"`` / ``b64``/``base64(..)``
    / ``b32``/``base32(..)``), or None if unrecognised.

    Thin wrapper over the canonical :func:`tealql.tealtools.ast.literals.
    decode_byte_literal`. This module previously carried its own copy, which had
    drifted: its string decoder emitted ``ord(c)`` per character, so a non-ASCII
    literal like ``byte "caf\u00e9"`` normalised to ``636166e9`` instead of the
    assembler's UTF-8 ``636166c3a9`` — every guard comparing against that
    constant then mis-evaluated. One decoder, one behaviour.
    """
    from .ast.literals import decode_byte_literal
    try:
        raw, _kind = decode_byte_literal(v.strip())
    except Exception:
        return None
    return raw


def _strip_inline_comment(code: str) -> str:
    """Drop a ``//`` inline comment that sits OUTSIDE a quoted string."""
    q = False
    for i in range(len(code) - 1):
        if code[i] == '"' and (i == 0 or code[i - 1] != "\\"):
            q = not q
        elif not q and code[i:i + 2] == "//":
            return code[:i]
    return code


#: a ``byte`` / ``method`` / ``addr`` pseudo-op at line start (after indent),
#: followed by ANY whitespace — tab-separated forms count too.
_PSEUDO_OP_RE = re.compile(r"(?:^|\n)[ \t]*(?:byte|method|addr)[ \t]")

#: Real (non-pseudo) opcodes that take a byte-LITERAL operand list. The grammar
#: accepts ``0x..`` and ``"str"`` for these but NOT the ``base64(..)`` /
#: ``b64(..)`` / ``base32(..)`` / ``b32(..)`` encodings the assembler allows, so
#: such a line parses as an ERROR and the opcode keeps EMPTY immediates — the
#: constant is gone. For ``bytecblock`` that is severe: every ``bytec_N``
#: reference in the program then resolves to nothing. Puya emits exactly this
#: (``bytecblock base64(DIEBQw==)``) for embedded program bytes.
_BYTE_LITERAL_OPS = frozenset({"pushbytes", "pushbytess", "bytecblock"})

#: The encodings the grammar chokes on, in either spelling and either form.
_BYTE_ENC_RE = re.compile(r"\b(?:b64|base64|b32|base32)\s*[( ]")

#: Ops whose operand is a LABEL (so a path-mangled label must be renamed there
#: too). ``b`` is the bare branch — ``b+`` / ``b-`` etc. are different tokens and
#: do not match, since the comparison is against the whole first token.
_LABEL_REF_OPS = frozenset({"b", "bz", "bnz", "callsub", "match", "switch"})


def _sanitize_path_labels(text: str) -> str:
    """Mangle grammar-unsafe ``/`` and ``.`` inside LABELS to ``_``.

    puya-sol emits full source paths as subroutine labels
    (``callsub /home/dev/contracts/Token.sol.transfer``). The tree-sitter-teal
    grammar's label token stops at the first ``/``, so the target truncates to
    ``/home``, the rest of the path parses as a run of bare ``/`` division
    opcodes, and the subroutine is never resolved — five parse diagnostics and
    an empty label set on a contract that is perfectly well-formed TEAL.

    The rename is applied CONSISTENTLY to the label's definition and to every
    branch / callsub / match / switch reference, so it is bijective and leaves
    the CFG identical. It is char-for-char (``/`` and ``.`` both become one
    ``_``), so line lengths are preserved and every node's column span stays
    valid. Only label-definition and label-reference lines are touched — never
    the ``/`` division opcode, never a numeric or hex operand.

    A no-op when no label contains ``/`` or ``.``. If two distinct labels would
    mangle to the SAME name (or onto a label already present), that rename is
    dropped rather than silently merging two blocks."""
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
    # Drop any rename that would collide — with another mangled label, or with a
    # label that already exists under that name. Merging two blocks would corrupt
    # the CFG far worse than the truncation this works around.
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

    The grammar's string tokenizer runs past the ``//`` when the comment holds
    a ``"``, so `pushbytes "asa_"   // [name, "asa_"]` parses with the
    string_argument `'"asa_"   // [name,'` — the comment text becomes PART OF
    THE CONSTANT. A guard comparing against that value can never match, and
    nothing reports a problem; only a stray `]` shows up as a diagnostic
    elsewhere on the line.

    Replaced with spaces rather than deleted, so line lengths — and therefore
    every column span — are preserved exactly. Only comments containing a quote
    are touched; ordinary comments parse fine and are left for the grammar.
    Our own :func:`_strip_inline_comment` already finds the boundary correctly
    (it tracks quote state), so the split is reliable."""
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
    ``store:`` / ``get:`` …), consistently at the definition and every
    reference.

    The grammar tokenizes ``pop:`` as the ``pop`` OPCODE followed by a stray
    ``:``, so the label is never defined: it vanishes from ``prog.labels``, and
    every ``b``/``match``/``switch`` that targets it loses its CFG edge. Puya
    names a router label after the ABI method, and methods called ``get`` /
    ``set`` / ``pop`` / ``append`` / ``concat`` / ``store`` are entirely
    ordinary — this accounts for most of the residual parse failures in the
    corpus (a single ``match`` line with four such targets emits four).

    Renaming is bijective, so the CFG is unchanged. Unlike
    :func:`_sanitize_path_labels` it does NOT preserve line length (a suffix
    must be added); that is fine because every span is computed against this
    normalized text, and line NUMBERS — the thing findings report — are
    untouched.

    Replacement is token-wise, never a substring sweep: a label named ``b`` on
    the line ``b b`` must rename the operand and leave the branch opcode alone.
    A rename that would collide with an existing label is dropped."""
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
    can be spotted. Derived from the AVM arity table, not re-listed."""
    from .avm import SIG, _FRAME_OVERRIDES
    return frozenset(SIG) | frozenset(_FRAME_OVERRIDES) | frozenset({
        "dig", "bury", "cover", "uncover", "popn", "dupn",
        "pushints", "pushbytess", "match", "switch", "proto",
    })


#: SOURCE REWRITES applied, in order, before the grammar ever sees the text.
#: Each works around a construct tree-sitter-teal cannot parse, and each is a
#: no-op on source that does not contain it. Order matters: comments are
#: neutralised first (a quote inside one derails the string tokenizer), then
#: labels are made parseable, and only then does the per-line pseudo-op rewrite
#: below run. Kept as a named sequence rather than nested calls so the order is
#: legible and a new rewrite has an obvious place to go.
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
                # The 32-byte public key is the prefix (a full address adds a
                # 4-byte checksum -> 36 bytes). A decode SHORTER than 32 bytes
                # would truncate to a sub-32-byte `pushbytes` and silently corrupt
                # the constant — reject it so the parser handles the original line.
                new = f"pushbytes 0x{raw[:32].hex()}" if len(raw) >= 32 else None
            except Exception:
                new = None
        elif op in _BYTE_LITERAL_OPS and _BYTE_ENC_RE.search(operand):
            # Re-encode each operand to `0x..`, which the grammar DOES accept.
            # `tokenize_operands` already keeps a parenthesised `base64(..)`
            # group (and, folded, the `b64 <data>` pair) as ONE token, so an
            # operand list survives intact.
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
    """Yield ``(relpath, bytes)`` for each ``.teal`` under ``source``, pseudo-op-
    normalized (see :func:`_normalize_pseudo_ops`) so the parser sees only
    canonical opcodes.

    ``source`` is one of: a single ``.teal`` file, a directory containing ``.teal``
    files, **or an in-memory mapping** ``{name: str | bytes}`` of TEAL source -- the
    last form lets the whole pipeline (graph -> SSA -> lift -> analysis) run with no
    filesystem at all (editor integrations, fuzzing, tests without temp files).
    """
    if isinstance(source, Mapping):
        for name, text in source.items():
            data = text.encode("utf-8") if isinstance(text, str) else text
            yield name, _normalize_pseudo_ops(data)
        return
    source = Path(source)
    if source.is_file() and source.suffix == ".teal":
        yield source.name, _normalize_pseudo_ops(source.read_bytes())
        return
    if source.is_dir():
        for f in sorted(source.glob("*.teal")):
            yield f.name, _normalize_pseudo_ops(f.read_bytes())


def _load_source_bytes(source: Path) -> dict[str, bytes]:
    """Map basename -> raw source bytes (keyed by basename, the relative path the
    ``ast.parse`` pass reports for each node)."""
    return {Path(rel).name: data for rel, data in _resolve_source_files(source)}


def _slice_source(sources: dict[str, list[str]], loc: Location) -> str:
    """Extract the source text covered by a :class:`Location`.

    Lines are 1-based; columns are native 0-based half-open ``[start, end)``.
    TEAL opcodes are always single-line; for multi-line spans (e.g. the
    program-root ``Source`` node) we return ``""`` since the covered region
    isn't a single statement.
    """
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
    """Build a MultiDiGraph from a TEAL source.

    Parameters
    ----------
    source:
        A raw ``.teal`` file, a directory of ``.teal`` files, **or** an in-memory
        mapping ``{name: str | bytes}`` of TEAL source (no filesystem). All run the
        same pure-Python pipeline.
    """
    if isinstance(source, Mapping):
        g_source = "<memory>"
    else:
        source = Path(source).resolve()
        if not source.exists():
            raise FileNotFoundError(source)
        g_source = str(source)

    g = nx.MultiDiGraph()
    g.graph["source"] = g_source

    # (file, start_line) -> AstNode, for the const-value mapping below.
    by_loc: dict[tuple[str, int], AstNode] = {}

    # Pass 1: parse the source into AstNode objects. Pass 2: derive the
    # control-flow edges + basic blocks from them. No relational intermediate --
    # the same objects flow through both passes and into the graph.
    from .ast.parse import parse_nodes
    from .cfg_build import build_cfg_edges, build_basic_blocks
    parse_diags: list = []
    nodes = parse_nodes(_load_source_bytes(source), diagnostics=parse_diags)
    # Unparseable spans the grammar dropped. Non-empty => the graph (and
    # everything built on it) covers only PART of the source; consumers
    # surface this via SSAProgram.parse_diagnostics.
    g.graph["parse_diagnostics"] = tuple(parse_diags)
    for node in nodes:
        by_loc[(node.location.file, node.location.start_line)] = node
        g.add_node(node)
    for u, v, t in build_cfg_edges(nodes):
        g.add_edge(u, v, kind="cfg", successor=t)
    for node, bb_first, bb_last in build_basic_blocks(nodes):
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


