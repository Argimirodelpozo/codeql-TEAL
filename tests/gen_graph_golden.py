"""Regenerate the graph-fact golden fixtures (see ``graph_golden``).

Writes ``<contract>/graph_golden.txt`` for every fixture under ``tests/tealtools``
and ``tests/contracts`` that carries source. Run after an intentional change to the
``nodes`` / ``cfgEdges`` / ``basicBlocks`` producers::

    python -m tests.gen_graph_golden          # all contracts
    python -m tests.gen_graph_golden <contract>...  # specific contracts
"""
from __future__ import annotations

import difflib
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


def _print_diff(path: Path, old: str, new: str) -> None:
    """Show what a regen changes BEFORE it lands, so a behaviour change can never
    be absorbed silently into 149 goldens (findings.md 4.5)."""
    diff = "\n".join(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile=f"{path} (old)", tofile=f"{path} (new)", lineterm=""))
    print(diff or f"{path}: unchanged")


def main(argv: list[str]) -> int:
    contracts = [Path(a) for a in argv] if argv else _all_contracts()
    written = changed = skipped = 0
    for contract in contracts:
        text = compute_golden(contract)
        if text is None:
            skipped += 1
            continue
        path = golden_path(contract)
        old = path.read_text() if path.exists() else ""
        if old != text:
            changed += 1
            _print_diff(path, old, text)
        path.write_text(text)
        written += 1
    print(f"wrote {written} golden(s), {changed} changed, skipped {skipped} (no source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
