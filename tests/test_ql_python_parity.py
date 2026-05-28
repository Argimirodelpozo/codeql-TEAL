"""Differential parity tests for the QL→Python query ports.

Each ported query's pure-Python reimplementation must produce row-for-row
identical output to the kept ``.ql`` file, on every fixture DB. The ``.ql``
files stay in ``queries/`` precisely so they remain available as ground
truth here, even after they're dropped from ``graphs.QUERY_NAMES``.

Run just these::

    pytest tests/test_ql_python_parity.py -q
"""
import os
from pathlib import Path

import pytest

from tealtools import graphs
from tealtools.ast import Opcode
from tealtools.graphs import (
    QUERIES_DIR,
    _cache_dir_for,
    _read_csv,
    _run_csv_query,
)
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
