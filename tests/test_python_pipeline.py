"""Pure-Python graph-pipeline tests — exercise the ``ast_build`` +
``cfg_build`` producers and the Python-backend ``load_graph`` WITHOUT
codeql.

These complement ``test_ql_python_parity`` (which needs codeql to compare
against the kept ``.ql`` ground truth). Here we assert the producers are
self-consistent and that the loaded graph is well-formed — so the pipeline
keeps working in environments with no codeql / JVM at all.
"""
import os
from pathlib import Path

import pytest

from tealtools.graphs import (
    load_graph,
    _load_source_bytes,
    _load_source_lines,
)
from tealtools.ast_build import build_nodes
from tealtools.cfg_build import build_cfg_edges, build_basic_blocks

TESTS_DIR = Path(__file__).resolve().parent

_SUCC_TYPES = {"NormalSuccessor", "BooleanSuccessor(true)", "BooleanSuccessor(false)"}


def _all_dbs() -> list[Path]:
    dbs: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "dbs"):
        if root.exists():
            for yml in sorted(root.rglob("codeql-database.yml")):
                if (yml.parent / "src.zip").exists():
                    dbs.append(yml.parent)
    return dbs


_DBS = _all_dbs()
_IDS = [str(d.relative_to(TESTS_DIR)) for d in _DBS]


@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_python_producers_selfconsistent(db: Path) -> None:
    """``build_nodes`` -> ``build_cfg_edges`` / ``build_basic_blocks`` are
    internally consistent: one ``Source`` row per file, every CFG/BB endpoint
    is a real node line, every successor type is one of the three known
    strings. No codeql."""
    src_bytes = _load_source_bytes(db)
    if not src_bytes:
        pytest.skip("no source in db")
    nodes = build_nodes(src_bytes)
    assert nodes, "no nodes produced"

    files = {r[0] for r in nodes}
    source_rows = [r for r in nodes if r[5] == "Source"]
    assert len(source_rows) == len(files), "exactly one Source row per file"

    node_lines = {(r[0], r[1]) for r in nodes if r[5] != "Source"}

    lines = _load_source_lines(db)
    edges = build_cfg_edges(nodes, lines)
    bbs = build_basic_blocks(nodes, lines)

    for sf, sl, df, dl, t in edges:
        assert (sf, sl) in node_lines, f"cfg edge source {sf}:{sl} not a node"
        assert (df, dl) in node_lines, f"cfg edge dest {df}:{dl} not a node"
        assert t in _SUCC_TYPES, f"unknown successor type {t!r}"

    for f, ln, first, last in bbs:
        assert (f, ln) in node_lines, f"bb member {f}:{ln} not a node"
        assert (f, first) in node_lines, f"bb first {f}:{first} not a node"
        assert (f, last) in node_lines, f"bb last {f}:{last} not a node"
        assert first <= ln <= last, f"bb member {ln} outside [{first},{last}]"


@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_python_load_graph_wellformed(db: Path, monkeypatch) -> None:
    """``load_graph`` on the Python backend builds a well-formed graph with
    no codeql: nodes present, every CFG edge endpoint is a graph node, every
    ``bb`` annotation is a 3-tuple. No codeql."""
    monkeypatch.setenv("TEAL_GRAPHS_BACKEND", "python")
    g = load_graph(db, verbose=False)
    assert g.number_of_nodes() > 0

    for u, v, d in g.edges(data=True):
        assert u in g and v in g
        if d.get("kind") == "cfg":
            assert d.get("successor") in _SUCC_TYPES

    for n in g.nodes:
        bb = g.nodes[n].get("bb")
        if bb is not None:
            assert len(bb) == 3 and bb[1] <= bb[2]


# A handful of representative real contracts for the heavier SSA check.
_REAL = [d for d in _DBS if d.parent.name == "dbs" or d.name.endswith("-db")]
_REAL_IDS = [str(d.relative_to(TESTS_DIR)) for d in _REAL]


@pytest.mark.parametrize("db", _REAL, ids=_REAL_IDS)
def test_python_backend_builds_ssa(db: Path, monkeypatch) -> None:
    """The Python-backend graph drives SSA construction end to end (no
    codeql): ``SSAProgram(db)`` builds and yields at least one block."""
    monkeypatch.setenv("TEAL_GRAPHS_BACKEND", "python")
    from tealtools.ssa import SSAProgram

    prog = SSAProgram(str(db))
    assert prog.blocks, "SSA produced no basic blocks"


@pytest.mark.parametrize("db", _REAL, ids=_REAL_IDS)
def test_raw_teal_no_codeql(db: Path, monkeypatch, tmp_path) -> None:
    """The whole pipeline runs on a raw ``.teal`` file/dir (no codeql DB):
    ``load_graph`` builds the same graph whether handed the DB or the extracted
    source, and ``SSAProgram`` builds from raw TEAL. Proves codeql is gone from
    the runtime path."""
    import zipfile
    monkeypatch.setenv("TEAL_GRAPHS_BACKEND", "python")
    with zipfile.ZipFile(db / "src.zip") as zf:
        members = [n for n in zf.namelist() if n.endswith(".teal")]
        if not members:
            pytest.skip("no teal in db")
        raw = tmp_path / Path(members[0]).name
        raw.write_bytes(zf.read(members[0]))

    g_db = load_graph(db, verbose=False)
    g_file = load_graph(raw, verbose=False)              # raw .teal file
    g_dir = load_graph(tmp_path, verbose=False)          # dir of .teal
    assert g_db.number_of_nodes() == g_file.number_of_nodes() == g_dir.number_of_nodes()
    assert g_db.number_of_edges() == g_file.number_of_edges() == g_dir.number_of_edges()

    from tealtools.ssa import SSAProgram
    assert SSAProgram(str(raw)).blocks, "SSA from raw TEAL produced no blocks"


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _REAL, ids=_REAL_IDS)
def test_python_vs_codeql_backend_equivalent(db: Path, monkeypatch) -> None:
    """The Python and codeql backends build the same graph: identical node
    locations, CFG edges (by location + successor), and BB annotations. The
    only allowed node-class difference is the ``==`` / ``!=`` dual-class
    dedup winner (behaviourally irrelevant — nothing references those leaf
    classes), so node identity is compared by location, not class."""
    def summarize(g):
        node_locs = {(n.location.file, n.location.start_line) for n in g.nodes}
        cfg = {
            (u.location.file, u.location.start_line,
             v.location.file, v.location.start_line, d.get("successor"))
            for u, v, d in g.edges(data=True) if d.get("kind") == "cfg"
        }
        bb = {
            (n.location.file, n.location.start_line, g.nodes[n]["bb"])
            for n in g.nodes if g.nodes[n].get("bb") is not None
        }
        return node_locs, cfg, bb

    monkeypatch.setenv("TEAL_GRAPHS_BACKEND", "python")
    py = summarize(load_graph(db, verbose=False))
    monkeypatch.setenv("TEAL_GRAPHS_BACKEND", "codeql")
    ql = summarize(load_graph(db, verbose=False, refresh=True))
    assert py[0] == ql[0], "node-location set differs"
    assert py[1] == ql[1], "cfg-edge set differs"
    assert py[2] == ql[2], "basic-block annotation set differs"
