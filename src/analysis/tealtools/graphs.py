"""TEAL graph layer.

Build a NetworkX MultiDiGraph from TEAL source: typed
:class:`tealtools.ast.AstNode` nodes (one per opcode, hashed by
``(file, line)``) connected by ``kind="cfg"`` edges carrying a ``successor``
label. The extractor floor (``nodes`` / ``cfgEdges`` / ``basicBlocks``, see
``QUERY_NAMES``) is produced in pure Python by :mod:`tealtools.ast_build` +
:mod:`tealtools.cfg_build`; SSA / phis / const values / taint are reconstructed
in Python downstream (``tealtools.ssa``). CodeQL is not a dependency.

The source may be a CodeQL database directory (its ``src.zip`` is read), a
single ``.teal`` file, or a directory of ``.teal`` files — all run the same
pure-Python pipeline.

Quick start
-----------
    >>> from tealtools.graphs import load_graph
    >>> from .ast import Opcode, IntegerAddOpcode
    >>> g = load_graph("tests/dbs/xgov-db")     # or a raw .teal file / dir
    >>> [n for n in g if isinstance(n, IntegerAddOpcode)]

Graphviz rendering of the loaded graph lives in :mod:`tealtools.viz`
(``to_dot`` / ``draw_cfg`` / ``cfg_bb_graph`` / ``draw_cfg_bb``).
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

import networkx as nx

from .ast import AstNode, Location, ast_node_from_row

QUERY_NAMES = (
    "nodes",
    "cfgEdges",
    "basicBlocks",
)
# These three fact-sets — the extractor floor — are produced in pure Python by
# ``ast_build`` (nodes) and ``cfg_build`` (cfgEdges / basicBlocks). Everything
# above them (SSA, phis, const values, taint flow) is reconstructed in Python
# downstream. The former CodeQL queries that produced these (and the dropped
# ssaInputs/ssaOutputs/constValues/mustValues/phi* queries) are gone.


def _resolve_source_files(db: Path):
    """Yield ``(relpath, bytes)`` for each ``.teal`` source under ``db``.

    ``db`` may be a CodeQL database directory (read its ``src.zip``), a single
    ``.teal`` file, or a directory containing ``.teal`` files. The first form
    keeps the existing codeql-DB behaviour; the latter two let the whole
    pipeline (graph -> SSA -> lift -> analysis) run on raw TEAL with no codeql
    at all — there is nothing codeql-specific left in the runtime path.
    """
    db = Path(db)
    src_zip = db / "src.zip"
    if src_zip.exists():
        with zipfile.ZipFile(src_zip) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".teal"):
                    continue
                yield info.filename, zf.read(info.filename)
        return
    if db.is_file() and db.suffix == ".teal":
        yield db.name, db.read_bytes()
        return
    if db.is_dir():
        for f in sorted(db.glob("*.teal")):
            yield f.name, f.read_bytes()


def _load_source_lines(db: Path) -> dict[str, list[str]]:
    """Map relative path (and basename) -> 1-indexed source lines, from a
    codeql DB's ``src.zip`` or raw ``.teal`` file/dir."""
    sources: dict[str, list[str]] = {}
    for rel, data in _resolve_source_files(db):
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        sources[rel] = lines
        sources[Path(rel).name] = lines
    return sources


def _load_source_bytes(db: Path) -> dict[str, bytes]:
    """Map basename -> raw source bytes, from a codeql DB's ``src.zip`` or raw
    ``.teal`` file/dir.

    Keyed by basename to match the relative path CodeQL reports in ``nodes``
    (CodeQL strips the source-root prefix, so a file stored in the zip as
    ``tmp/dbsrc/x.teal`` surfaces as ``x.teal``). Used by the pure-Python
    ``ast_build`` producer.
    """
    return {Path(rel).name: data for rel, data in _resolve_source_files(db)}


def _slice_source(sources: dict[str, list[str]], loc: Location) -> str:
    """Extract the source text covered by a :class:`Location`.

    CodeQL columns are 1-based, inclusive at both ends. TEAL opcodes are
    always single-line; for multi-line spans (e.g. the program-root
    ``Source`` node) we return ``""`` since the covered region isn't a
    single statement.
    """
    lines = sources.get(loc.file) or sources.get(Path(loc.file).name)
    if lines is None:
        return ""
    if loc.start_line != loc.end_line:
        return ""
    if loc.start_line < 1 or loc.start_line > len(lines):
        return ""
    return lines[loc.start_line - 1][loc.start_column - 1 : loc.end_column]


def load_graph(
    db_path: str | Path,
    *,
    verbose: bool = True,
) -> nx.MultiDiGraph:
    """Build a MultiDiGraph from a TEAL source.

    Parameters
    ----------
    db_path:
        A CodeQL database directory (its ``src.zip`` is read), **or** a raw
        ``.teal`` file, **or** a directory of ``.teal`` files. All run the same
        pure-Python pipeline — no codeql.
    verbose:
        Accepted for backward compatibility; the pure-Python build is ~ms and
        prints nothing.
    """
    db = Path(db_path).resolve()
    if not db.exists():
        raise FileNotFoundError(db)

    g = nx.MultiDiGraph()
    g.graph["db_path"] = str(db)
    sources = _load_source_lines(db)

    # (file, start_line) -> AstNode instance, for edge-endpoint lookup.
    by_loc: dict[tuple[str, int], AstNode] = {}

    def _resolve(file: str, line: int) -> AstNode:
        key = (file, line)
        node = by_loc.get(key)
        if node is None:
            # Edge endpoint not reported by nodes — stash a bare AstNode
            # so the edge still lands in the graph.
            node = ast_node_from_row(Location(file, line, 0, line, 0), "", "AstNode")
            by_loc[key] = node
            g.add_node(node)
        return node

    # The three fact-sets, produced in pure Python (``ast_build`` + ``cfg_build``).
    from .ast_build import build_nodes
    from .cfg_build import build_cfg_edges, build_basic_blocks
    node_rows = build_nodes(_load_source_bytes(db))
    rows_by_query = {
        "nodes": node_rows,
        "cfgEdges": build_cfg_edges(node_rows, sources),
        "basicBlocks": build_basic_blocks(node_rows, sources),
    }

    for q in QUERY_NAMES:
        rows = rows_by_query[q]

        if q == "nodes":
            for file, sl, sc, el, ec, ql_class in rows:
                loc = Location(file, int(sl), int(sc), int(el), int(ec))
                code = _slice_source(sources, loc).strip()
                node = ast_node_from_row(loc, code, ql_class)
                by_loc[(file, loc.start_line)] = node
                g.add_node(node)
        elif q == "cfgEdges":
            for sf, sl, df, dl, t in rows:
                u = _resolve(sf, int(sl))
                v = _resolve(df, int(dl))
                g.add_edge(u, v, kind="cfg", successor=t)
        elif q == "basicBlocks":
            # Annotate each AstNode with its BB id = (file, firstLine, lastLine).
            for ast_file, ast_line, bb_first, bb_last in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                g.nodes[node]["bb"] = (ast_file, int(bb_first), int(bb_last))

    # constValues port: resolved literal constants per output, computed in
    # Python (replaces ``constValues.ql``). Populates ``const_outputs``
    # ``{out_idx: (kind, value)}`` and the single-output back-compat scalar
    # ``const_value`` — the same shape the QL handler produced.
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


