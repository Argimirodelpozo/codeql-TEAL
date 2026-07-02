"""Graph-fact producer tests — CodeQL-free (replaces ``test_ql_python_parity``).

The ``nodes`` / ``cfgEdges`` / ``basicBlocks`` producers were validated
row-for-row against fresh CodeQL. CodeQL is no longer a dependency, so that
ground truth is frozen as a committed golden per contract (see :mod:`graph_golden`)
and we assert reproduction here. A producer change that alters any contract's facts
fails loudly with a diff; intended changes are landed by regenerating::

    python -m tests.gen_graph_golden

Correctness *beyond* regression (are the facts actually right?) is anchored by
the downstream consumers that execute this output: SSA construction
(``test_python_pipeline``), the lift (``test_lift_semantics``) and the live-AVM
behavioural suite. A wrong edge / block surfaces there as a malformed lift or a
behavioural divergence, not just a snapshot drift.
"""
from pathlib import Path

import pytest


from graph_golden import GOLDEN_NAME, compute_golden, golden_path

TESTS_DIR = Path(__file__).resolve().parent


def _all_contracts() -> list[Path]:
    # A fixture is a dir carrying its committed golden; its source is a `.teal`
    # file (slimmed fixtures) or (both read by the graph backend) -- the graph backend
    # reads either, so discover by the golden, not codeql-database.yml/src.zip.
    contracts: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "contracts"):
        if root.exists():
            for golden in sorted(root.rglob(GOLDEN_NAME)):
                contracts.append(golden.parent)
    return contracts


_CONTRACTS = _all_contracts()
_IDS = [str(d.relative_to(TESTS_DIR)) for d in _CONTRACTS]


@pytest.mark.parametrize("contract", _CONTRACTS, ids=_IDS)
def test_graph_facts_golden(contract: Path) -> None:
    """``build_nodes`` / ``build_cfg_edges`` / ``build_basic_blocks`` reproduce
    the committed golden for ``contract`` exactly."""
    golden = golden_path(contract)
    if not golden.exists():
        pytest.skip(f"no committed {GOLDEN_NAME} "
                    "(regenerate: python -m tests.gen_graph_golden)")
    actual = compute_golden(contract)
    assert actual is not None, "contract carries no source"
    expected = golden.read_text()
    if actual != expected:
        import difflib
        diff = "\n".join(difflib.unified_diff(
            expected.splitlines(), actual.splitlines(),
            fromfile="golden", tofile="actual", lineterm=""))
        pytest.fail(
            f"graph facts diverge from golden for {contract.relative_to(TESTS_DIR)} "
            "(if intended, regenerate via `python -m tests.gen_graph_golden`):\n"
            + diff[:6000])
