"""CodeQL-free golden fixtures for the graph-fact producers.

The graph layer (``nodes`` / ``cfgEdges`` / ``basicBlocks``) used to be validated
by ``test_ql_python_parity`` — a row-for-row differential against a *fresh
CodeQL* run of the kept ``.ql`` files. CodeQL is no longer a dependency, so that
ground truth is frozen instead: the producers' (previously QL-validated,
row-exact) output is captured as a committed golden per DB, and the test asserts
reproduction. Regression is caught exactly; correctness *beyond* regression is
anchored by the downstream SSA / ``test_lift_semantics`` / behavioural tests,
which execute the producers' output on a real AVM.

The golden lives next to its DB (``<db>/graph_golden.txt``): committed for the
in-repo ``tests/tealtools`` fixtures, local-only (gitignored) for the heavy
``tests/contracts`` real contracts. Regenerate after an intentional producer change::

    python -m tests.gen_graph_golden
"""
from __future__ import annotations

from pathlib import Path

from tealtools.ast.parse import parse_nodes
from tealtools.cfg_build import build_basic_blocks, build_cfg_edges
from tealtools.graph import _load_source_bytes

GOLDEN_NAME = "graph_golden.txt"


def golden_path(db: Path) -> Path:
    return Path(db) / GOLDEN_NAME


def compute_golden(db: Path) -> str | None:
    """Deterministic golden text (``nodes`` / ``cfgEdges`` / ``basicBlocks``
    sections, each sorted) for ``db``, or ``None`` if the DB has no source.

    The producers now return AstNode objects; flatten each back to its
    ``(file, line, …)`` tuple so the golden text pins the same data."""
    src_bytes = _load_source_bytes(db)
    if not src_bytes:
        return None
    nodes = parse_nodes(src_bytes)
    edges = build_cfg_edges(nodes)
    bbs = build_basic_blocks(nodes)

    def loc(n):
        ll = n.location
        return (ll.file, ll.start_line, ll.start_column, ll.end_line, ll.end_column)

    node_rows = [(*loc(n), n.node_class) for n in nodes]
    edge_rows = [(u.location.file, u.location.start_line,
                  v.location.file, v.location.start_line, t) for (u, v, t) in edges]
    bb_rows = [(n.location.file, n.location.start_line, first, last)
               for (n, first, last) in bbs]

    out: list[str] = []

    def section(name: str, rows) -> None:
        out.append(f"## {name}")
        out.extend("\t".join(str(c) for c in r) for r in sorted(rows))

    section("nodes", node_rows)
    section("cfgEdges", edge_rows)
    section("basicBlocks", bb_rows)
    return "\n".join(out) + "\n"
