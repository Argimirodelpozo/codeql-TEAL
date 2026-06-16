"""Differential parity tests for the QL→Python query ports.

Each ported query's pure-Python reimplementation must produce row-for-row
identical output to the kept ``.ql`` file, on every fixture DB. The ``.ql``
files stay in ``queries/`` precisely so they remain available as ground
truth here, even after they're dropped from ``graphs.QUERY_NAMES``.

Run just these::

    pytest tests/test_ql_python_parity.py -q
"""
import collections
import os
from pathlib import Path

import pytest

from tealtools import graphs
from tealtools.ast import Opcode
from tealtools.opcode_sigs import op_arity
from tealtools.graphs import (
    QUERIES_DIR,
    _cache_dir_for,
    _load_source_lines,
    _read_csv,
    _run_csv_query,
)
from tealtools.cfg_build import build_cfg_edges, build_basic_blocks
from tealtools.ast_build import build_nodes
from tealtools.const_values import compute_const_values, _opname

TESTS_DIR = Path(__file__).resolve().parent

# ``bytec`` / ``bytec_N`` resolution diverges from QL on purpose: QL reads
# ``bytecblock.getChild(i)`` and tree-sitter packs consecutive string
# literals into a single child, so ``bytec_1``+ mis-resolve (and
# ``bytec_2``/``bytec_3`` resolve to nothing). The Python port indexes the
# literals correctly. We exclude ``bytec*`` op lines from the parity
# assertion and validate everything else (ints, pushbytes, pushints,
# pushbytess) row-for-row.
_BYTEC_OPS = frozenset({"bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3"})
_INTC_OPS = frozenset({"intc", "intc_0", "intc_1", "intc_2", "intc_3"})


def _explainable(row, op_at: dict) -> bool:
    """A PY-only ``constValues`` row that QL's own limits legitimately
    omit: an int outside CodeQL's 32-bit signed range (QL ``.toInt()``
    yields no result, so the row never appears), or an ``intc`` whose
    ``intcblock`` doesn't dominate it (dead / non-dominated code) — the
    port resolves the single intcblock eagerly. The port keeps the real
    value in both cases; the full suite is the arbiter of whether that
    extra precision changes any downstream result."""
    f, ln, _oi, kind, val = row
    if kind == "int":
        try:
            v = int(val)
        except ValueError:
            v = None
        if v is not None and not (-(2 ** 31) <= v <= 2 ** 31 - 1):
            return True
    return op_at.get((f, ln)) in _INTC_OPS


def _all_dbs() -> list[Path]:
    dbs: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "dbs"):
        if root.exists():
            for yml in sorted(root.rglob("codeql-database.yml")):
                dbs.append(yml.parent)
    return dbs


def _ql_rows(db: Path, qname: str) -> list[list[str]]:
    """Ground-truth rows from the kept ``.ql`` file (cached per-db)."""
    cache = _cache_dir_for(db)
    csv = cache / f"{qname}.csv"
    if not csv.exists():
        _run_csv_query(db, QUERIES_DIR / f"{qname}.ql", cache)
    return _read_csv(csv)


def _fmt_diff(ql: list, py: list, limit: int = 25) -> str:
    only_ql = sorted(set(ql) - set(py))
    only_py = sorted(set(py) - set(ql))
    lines = [
        f"\nQL={len(ql)} PY={len(py)}  "
        f"only_QL={len(only_ql)} only_PY={len(only_py)}"
    ]
    for r in only_ql[:limit]:
        lines.append(f"  -QL  {r}")
    for r in only_py[:limit]:
        lines.append(f"  +PY  {r}")
    return "\n".join(lines)


_DBS = _all_dbs()
_IDS = [str(d.relative_to(TESTS_DIR)) for d in _DBS]


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_constvalues_parity(db: Path) -> None:
    g = graphs.load_graph(str(db), verbose=False)
    op_at = {
        (n.location.file, n.location.start_line): _opname(n)
        for n in g.nodes if isinstance(n, Opcode)
    }
    bytec_lines = {k for k, v in op_at.items() if v in _BYTEC_OPS}
    keep = lambda row: (row[0], row[1]) not in bytec_lines
    ql = set(filter(keep, (
        (r[0], int(r[1]), int(r[2]), r[3], r[4])
        for r in _ql_rows(db, "constValues")
    )))
    py = set(filter(keep, (
        (f, int(ln), int(oi), k, v)
        for (f, ln, oi, k, v) in compute_const_values(g)
    )))
    # The port must reproduce every QL constant exactly — no misses, no
    # value mismatches. (A wrong reachable value shows up here too, since
    # QL's correct row lands in only_QL.)
    only_ql = sorted(ql - py)
    assert not only_ql, _fmt_diff(sorted(ql), sorted(py))
    # PY may emit extras only where QL's own limits exclude a constant.
    unexplained = [r for r in sorted(py - ql) if not _explainable(r, op_at)]
    assert not unexplained, "unexpected PY-only rows:\n" + "\n".join(
        f"  +PY {r}" for r in unexplained
    )


# Height-dependent ops: op_arity returns the simple phase-1 counts PySSA
# expects; their fat/proto-aware forms are rebuilt by later PySSA phases,
# so they intentionally diverge from QL's ssaOutputs/ssaInputs counts.
_HEIGHT_DEP_OPS = frozenset({"frame_dig", "frame_bury", "retsub"})


def _ops(g):
    for n in g.nodes:
        if isinstance(n, Opcode):
            code = n.code or n.ql_class or ""
            op, _, imms = code.partition(" ")
            yield n.location.file, n.location.start_line, op, imms.strip()


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_cfgedges_parity(db: Path) -> None:
    """``cfg_build.build_cfg_edges`` must reproduce ``cfgEdges.ql`` exactly.

    Consumes the ``nodes`` fact-set (still tree-sitter / QL) plus source
    text, and rebuilds every CFG edge in Python -- including the
    reachability prune that QL's ``CfgImpl`` applies (only nodes reachable
    from the entry appear). Row-for-row identical, both directions.
    """
    ql = set(
        (r[0], int(r[1]), r[2], int(r[3]), r[4]) for r in _ql_rows(db, "cfgEdges")
    )
    nodes = _ql_rows(db, "nodes")
    py = set(build_cfg_edges(nodes, _load_source_lines(db)))
    assert ql == py, _fmt_diff(sorted(ql), sorted(py))


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_basicblocks_parity(db: Path) -> None:
    """``cfg_build.build_basic_blocks`` must reproduce ``basicBlocks.ql``
    exactly: one ``(file, nodeLine, bbFirstLine, bbLastLine)`` row per
    reachable CFG node. In TEAL a basic block == a codeblock, so the
    partition is structural, intersected with CFG reachability."""
    ql = set(
        (r[0], int(r[1]), int(r[2]), int(r[3])) for r in _ql_rows(db, "basicBlocks")
    )
    nodes = _ql_rows(db, "nodes")
    py = set(build_basic_blocks(nodes, _load_source_lines(db)))
    assert ql == py, _fmt_diff(sorted(ql), sorted(py))


def _db_sources(db: Path, ql_files: set[str]) -> dict:
    """Map each QL file label to its raw source bytes from ``db/src.zip``,
    matched by basename (QL reports relative paths; the zip members may be
    basenames or subdir'd)."""
    import zipfile
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(db / "src.zip") as zf:
        for n in zf.namelist():
            if n.endswith(".teal"):
                members[Path(n).name] = zf.read(n)
    return {f: members[Path(f).name] for f in ql_files if Path(f).name in members}


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_nodes_parity(db: Path) -> None:
    """``ast_build.build_nodes`` must reproduce ``nodes.ql`` exactly: one row
    per opcode (with its most-specific leaf class), plus ``Label`` rows and
    the program-root ``Source`` row. Parsed with the same tree-sitter-teal
    grammar; ``==`` / ``!=`` emit two rows (Integer* + *Comparison)."""
    ql = set(
        (r[0], int(r[1]), int(r[2]), int(r[3]), int(r[4]), r[5])
        for r in _ql_rows(db, "nodes")
    )
    sources = _db_sources(db, {r[0] for r in ql})
    py = set(build_nodes(sources))
    assert ql == py, _fmt_diff(sorted(ql), sorted(py))


@pytest.mark.skipif("CODEQL" not in os.environ, reason="needs codeql")
@pytest.mark.parametrize("db", _DBS, ids=_IDS)
def test_opcode_arity_parity(db: Path) -> None:
    """op_arity must reproduce QL's ssaOutputs count exactly (n_out), and
    never under-count inputs vs QL's ssaInputs (n_in >= QL's resolved
    count; QL drops boundary-unresolvable inputs, so the port may exceed)."""
    g = graphs.load_graph(str(db), verbose=False)
    out_count: dict = collections.Counter()
    for r in _ql_rows(db, "ssaOutputs"):       # (file, line, outIdx)
        out_count[(r[0], int(r[1]))] += 1
    in_ord: dict = collections.defaultdict(set)
    for r in _ql_rows(db, "ssaInputs"):        # (file, line, ord, ...)
        in_ord[(r[0], int(r[1]))].add(r[2])

    out_bad, in_bad = [], []
    for f, ln, op, imms in _ops(g):
        if op in _HEIGHT_DEP_OPS:
            continue
        n_in, n_out = op_arity(op, imms)
        if n_out != out_count.get((f, ln), 0):
            out_bad.append((f, ln, op, imms, n_out, out_count.get((f, ln), 0)))
        if n_in < len(in_ord.get((f, ln), ())):
            in_bad.append((f, ln, op, imms, n_in, len(in_ord[(f, ln)])))
    assert not out_bad, "n_out != QL ssaOutputs:\n" + "\n".join(
        f"  {b}" for b in out_bad[:30])
    assert not in_bad, "n_in < QL ssaInputs (port lost an input):\n" + "\n".join(
        f"  {b}" for b in in_bad[:30])
