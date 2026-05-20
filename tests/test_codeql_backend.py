"""Pytest wrapper for CodeQL native backend tests.

Discovers every ``test.ql`` under ``tests/codeql/`` and runs
``codeql test run`` against it, asserting the test passes (i.e.
its output matches the checked-in ``test.expected`` baseline).

The expected file is regenerated with::

    UPDATE_SNAPSHOTS=1 pytest tests/test_codeql_backend.py

which passes ``--learn`` to the underlying ``codeql test run``.
Same env-var convention as the tealtools snapshot harness.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SEARCH_PATH = REPO_ROOT / ".codeql-extractors"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Where to find CodeQL native tests. Each directory listed here is
# walked recursively for ``*.ql`` / ``*.qlref`` files; any whose
# sibling ``*.expected`` file exists is treated as a test.
TEST_ROOTS = [
    Path(__file__).resolve().parent / "codeql",
]


def _codeql_binary() -> str | None:
    return os.environ.get("CODEQL") or shutil.which("codeql")


def _discover():
    seen: set[Path] = set()
    paths: list[Path] = []
    for root in TEST_ROOTS:
        if not root.exists():
            continue
        for path in list(root.rglob("*.ql")) + list(root.rglob("*.qlref")):
            # Skip pack-cache artefacts.
            if ".codeql" in path.parts:
                continue
            # `.qlref` files are explicit tests by their existence
            # (so UPDATE_SNAPSHOTS can bootstrap their baselines).
            # Loose `.ql` files only count as tests when paired with
            # an `.expected` baseline (otherwise they're production
            # queries, not tests).
            if path.suffix == ".ql" and not path.with_suffix(".expected").exists():
                continue
            if path in seen:
                continue
            seen.add(path)
            paths.append(path)
    for path in sorted(paths):
        rel = path.relative_to(REPO_ROOT)
        yield pytest.param(path, id=str(rel))


@pytest.mark.parametrize("ql_path", list(_discover()))
def test_codeql_query(ql_path: Path) -> None:
    codeql = _codeql_binary()
    if codeql is None:
        pytest.skip("codeql binary not found (set CODEQL or add to PATH)")

    cmd = [codeql, "test", "run", f"--search-path={SEARCH_PATH}"]
    if UPDATE:
        cmd.append("--learn")
    cmd.append(str(ql_path))

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        rel = ql_path.relative_to(REPO_ROOT)
        pytest.fail(
            f"codeql test failed for {rel}:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
            "Re-run with UPDATE_SNAPSHOTS=1 to refresh the baseline."
        )
