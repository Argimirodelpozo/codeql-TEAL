"""Graph-pipeline tests — exercise the ``ast.parse`` + ``cfg_build`` passes
and ``load_graph``.

These complement ``test_graph_golden`` (which pins the passes' exact output to
committed golden fixtures). Here we assert the passes are self-consistent and that
the loaded graph is well-formed.
"""
from pathlib import Path

import pytest

from tealtools.graph import load_graph, _load_source_bytes
from tealtools.ast.parse import parse_nodes
from tealtools.cfg_build import build_cfg_edges, build_basic_blocks

TESTS_DIR = Path(__file__).resolve().parent

_SUCC_TYPES = {"NormalSuccessor", "BooleanSuccessor(true)", "BooleanSuccessor(false)"}


def _all_dbs() -> list[Path]:
    # Fixtures carry a committed golden; source is a `.teal` file (slimmed) or a
    # legacy codeql `src.zip` -- discover by the golden, not codeql-database.yml.
    dbs: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "contracts"):
        if root.exists():
            for golden in sorted(root.rglob("graph_golden.txt")):
                dbs.append(golden.parent)
    return dbs


_DBS = _all_dbs()
_IDS = [str(d.relative_to(TESTS_DIR)) for d in _DBS]


@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_python_producers_selfconsistent(db: Path) -> None:
    """``parse_nodes`` -> ``build_cfg_edges`` / ``build_basic_blocks`` are
    internally consistent: one ``Source`` node per file, every CFG/BB endpoint is a
    real node line, every successor type is one of the three known strings."""
    src_bytes = _load_source_bytes(db)
    if not src_bytes:
        pytest.skip("no source in db")
    nodes = parse_nodes(src_bytes)
    assert nodes, "no nodes produced"

    def fl(n):
        return (n.location.file, n.location.start_line)

    files = {n.location.file for n in nodes}
    source_nodes = [n for n in nodes if n.node_class == "Source"]
    assert len(source_nodes) == len(files), "exactly one Source node per file"

    node_lines = {fl(n) for n in nodes if n.node_class != "Source"}

    edges = build_cfg_edges(nodes)
    bbs = build_basic_blocks(nodes)

    for u, v, t in edges:
        assert fl(u) in node_lines, f"cfg edge source {fl(u)} not a node"
        assert fl(v) in node_lines, f"cfg edge dest {fl(v)} not a node"
        assert t in _SUCC_TYPES, f"unknown successor type {t!r}"

    for node, first, last in bbs:
        f, ln = fl(node)
        assert (f, ln) in node_lines, f"bb member {f}:{ln} not a node"
        assert (f, first) in node_lines, f"bb first {f}:{first} not a node"
        assert (f, last) in node_lines, f"bb last {f}:{last} not a node"
        assert first <= ln <= last, f"bb member {ln} outside [{first},{last}]"


@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_python_load_graph_wellformed(db: Path) -> None:
    """``load_graph`` builds a well-formed graph: nodes present, every CFG
    edge endpoint is a graph node, every ``bb`` annotation is a 3-tuple."""
    g = load_graph(db)
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
_REAL = [d for d in _DBS if d.parent.name == "contracts"]
_REAL_IDS = [str(d.relative_to(TESTS_DIR)) for d in _REAL]


@pytest.mark.parametrize("db", _REAL, ids=_REAL_IDS)
def test_python_backend_builds_ssa(db: Path) -> None:
    """The graph drives SSA construction end to end: ``SSAProgram(db)``
    builds and yields at least one block."""
    from tealtools.ssa import SSAProgram

    prog = SSAProgram(str(db))
    assert prog.blocks, "SSA produced no basic blocks"


@pytest.mark.parametrize("db", _REAL, ids=_REAL_IDS)
def test_raw_teal_runs_end_to_end(db: Path, tmp_path) -> None:
    """The whole pipeline runs on a raw ``.teal`` file/dir: ``load_graph``
    builds the same graph whether handed the dir or the extracted source, and
    ``SSAProgram`` builds from raw TEAL."""
    teal_files = sorted(db.glob("*.teal"))
    if teal_files:                                       # slimmed fixture: .teal source
        srcs = {t.name: t.read_bytes() for t in teal_files}
    else:                                                # legacy codeql DB: from src.zip
        import zipfile
        with zipfile.ZipFile(db / "src.zip") as zf:
            srcs = {Path(n).name: zf.read(n) for n in zf.namelist() if n.endswith(".teal")}
    if not srcs:
        pytest.skip("no teal in db")
    for name, data in srcs.items():
        (tmp_path / name).write_bytes(data)
    raw = tmp_path / next(iter(srcs))                    # one extracted .teal

    g_db = load_graph(db)
    g_dir = load_graph(tmp_path)          # dir of extracted .teal
    assert g_db.number_of_nodes() == g_dir.number_of_nodes()
    assert g_db.number_of_edges() == g_dir.number_of_edges()
    if len(srcs) == 1:                                   # single-source: file form too
        g_file = load_graph(tmp_path / next(iter(srcs)))
        assert g_db.number_of_nodes() == g_file.number_of_nodes()
        assert g_db.number_of_edges() == g_file.number_of_edges()

    from tealtools.ssa import SSAProgram
    assert SSAProgram(str(raw)).blocks, "SSA from raw TEAL produced no blocks"
