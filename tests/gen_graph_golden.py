"""Regenerate the graph-fact golden fixtures (see ``graph_golden``).

Writes ``<contract>/graph_golden.txt`` for every fixture under ``tests/tealtools``
and ``tests/contracts`` that carries source. Run after an intentional change to the
``nodes`` / ``cfgEdges`` / ``basicBlocks`` producers::

    python -m tests.gen_graph_golden          # all contracts
    python -m tests.gen_graph_golden <contract>...  # specific contracts
"""
from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from graph_golden import GOLDEN_NAME, compute_golden, golden_path  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent


def _all_contracts() -> list[Path]:
    # Regenerate the golden for every fixture that already carries one; its source
    # is a `.teal` file (slimmed) or (both read by the graph backend) (both read by the
    # graph backend).
    contracts: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "contracts"):
        if root.exists():
            for golden in sorted(root.rglob(GOLDEN_NAME)):
                contracts.append(golden.parent)
    return contracts


def main(argv: list[str]) -> int:
    contracts = [Path(a) for a in argv] if argv else _all_contracts()
    written = skipped = 0
    for contract in contracts:
        text = compute_golden(contract)
        if text is None:
            skipped += 1
            continue
        golden_path(contract).write_text(text)
        written += 1
    print(f"wrote {written} golden(s), skipped {skipped} (no source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
