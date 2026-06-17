"""Graph-fact producer tests — CodeQL-free (replaces ``test_ql_python_parity``).

The ``nodes`` / ``cfgEdges`` / ``basicBlocks`` producers were validated
row-for-row against fresh CodeQL. CodeQL is no longer a dependency, so that
ground truth is frozen as a committed golden per DB (see :mod:`graph_golden`)
and we assert reproduction here. A producer change that alters any DB's facts
fails loudly with a diff; intended changes are landed by regenerating::

    python -m tests.gen_graph_golden

Correctness *beyond* regression (are the facts actually right?) is anchored by
the downstream consumers that execute this output: SSA construction
(``test_python_pipeline``), the lift (``test_lift_semantics``) and the live-AVM
behavioural suite. A wrong edge / block surfaces there as a malformed lift or a
behavioural divergence, not just a snapshot drift.
"""
import os
from pathlib import Path

import pytest

os.environ.setdefault("TEAL_GRAPHS_BACKEND", "python")

from graph_golden import GOLDEN_NAME, compute_golden, golden_path

TESTS_DIR = Path(__file__).resolve().parent


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
def test_graph_facts_golden(db: Path) -> None:
    """``build_nodes`` / ``build_cfg_edges`` / ``build_basic_blocks`` reproduce
    the committed golden for ``db`` exactly."""
    golden = golden_path(db)
    if not golden.exists():
        pytest.skip(f"no committed {GOLDEN_NAME} "
                    "(regenerate: python -m tests.gen_graph_golden)")
    actual = compute_golden(db)
    assert actual is not None, "DB carries no source"
    expected = golden.read_text()
    if actual != expected:
        import difflib
        diff = "\n".join(difflib.unified_diff(
            expected.splitlines(), actual.splitlines(),
            fromfile="golden", tofile="actual", lineterm=""))
        pytest.fail(
            f"graph facts diverge from golden for {db.relative_to(TESTS_DIR)} "
            "(if intended, regenerate via `python -m tests.gen_graph_golden`):\n"
            + diff[:6000])
