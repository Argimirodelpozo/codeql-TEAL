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


def _teal_str_bytes(s: str) -> bytes:
    """Decode a TEAL ``"..."`` string body (\\\\ \\" \\n \\r \\t \\xNN)."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 4 <= len(s):
                out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
            out.append({"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34}.get(n, ord(n)))
            i += 2; continue
        out.append(ord(c)); i += 1
    return bytes(out)


def _byte_literal(v: str):
    """Raw bytes for a TEAL byte literal (``0x`` / ``"str"`` / ``b64``/``base64(..)``
    / ``b32``/``base32(..)``), or None if unrecognised."""
    v = v.strip()
    try:
        if v.startswith("0x"):
            return bytes.fromhex(v[2:])
        if v.startswith('"') and v.endswith('"'):
            return _teal_str_bytes(v[1:-1])
        if v.startswith(("b64 ", "base64 ")):
            b = v.split(None, 1)[1].strip()
            return base64.b64decode(b + "=" * (-len(b) % 4))
        if v.startswith("base64(") and v.endswith(")"):
            b = v[7:-1]
            return base64.b64decode(b + "=" * (-len(b) % 4))
        if v.startswith(("b32 ", "base32 ")):
            b = v.split(None, 1)[1].strip()
            return base64.b32decode(b + "=" * (-len(b) % 8))
        if v.startswith("base32(") and v.endswith(")"):
            b = v[7:-1]
            return base64.b32decode(b + "=" * (-len(b) % 8))
    except Exception:
        return None
    return None


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


def _normalize_pseudo_ops(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    if not _PSEUDO_OP_RE.search(text):
        return data                                # fast path: nothing to rewrite
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


