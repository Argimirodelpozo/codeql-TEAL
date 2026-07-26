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


def _normalize_pseudo_ops(data: bytes) -> bytes:
    text = _sanitize_path_labels(data.decode("utf-8", "replace"))
    if not _PSEUDO_OP_RE.search(text):
        return text.encode("utf-8")                # fast path: no pseudo-ops left
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


