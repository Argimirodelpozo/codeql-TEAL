"""Regenerate the graph-fact golden fixtures (see ``graph_golden``).

Writes ``<db>/graph_golden.txt`` for every fixture DB under ``tests/tealtools``
and ``tests/dbs`` that carries source. Run after an intentional change to the
``nodes`` / ``cfgEdges`` / ``basicBlocks`` producers::

    python -m tests.gen_graph_golden          # all DBs
    python -m tests.gen_graph_golden <db>...  # specific DBs
"""
from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from graph_golden import GOLDEN_NAME, compute_golden, golden_path  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent


def _all_dbs() -> list[Path]:
    # Regenerate the golden for every fixture that already carries one; its source
    # is a `.teal` file (slimmed) or a legacy codeql `src.zip` (both read by the
    # graph backend).
    dbs: list[Path] = []
    for root in (TESTS_DIR / "tealtools", TESTS_DIR / "dbs"):
        if root.exists():
            for golden in sorted(root.rglob(GOLDEN_NAME)):
                dbs.append(golden.parent)
    return dbs


def main(argv: list[str]) -> int:
    dbs = [Path(a) for a in argv] if argv else _all_dbs()
    written = skipped = 0
    for db in dbs:
        text = compute_golden(db)
        if text is None:
            skipped += 1
            continue
        golden_path(db).write_text(text)
        written += 1
    print(f"wrote {written} golden(s), skipped {skipped} (no source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
