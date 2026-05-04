"""Build CodeQL DBs for tealtools fixtures.

Walks every ``tests/tealtools/.../prog.teal`` and produces a
sibling ``db/`` via ``codeql database create`` if one isn't already
there. ``force=True`` rebuilds all of them. Idempotent — safe to
call before every pytest run via :mod:`tests.conftest`.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
TEALTOOLS_FIXTURES = Path(__file__).resolve().parent / "tealtools"
SEARCH_PATH = REPO_ROOT / ".codeql-extractors"


def _codeql() -> Optional[str]:
    return os.environ.get("CODEQL") or shutil.which("codeql")


def find_fixtures() -> list[Path]:
    """Every ``prog.teal`` under tealtools, sorted for determinism."""
    if not TEALTOOLS_FIXTURES.exists():
        return []
    return sorted(TEALTOOLS_FIXTURES.rglob("prog.teal"))


def build_db(prog_teal: Path, *, force: bool = False) -> bool:
    """Build the DB next to ``prog_teal`` if missing (or always when
    ``force``). Returns True if a build ran, False if it was skipped."""
    src = prog_teal.parent
    db = src / "db"
    if db.exists() and not force:
        return False
    codeql = _codeql()
    if codeql is None:
        raise RuntimeError(
            "codeql binary not found (set $CODEQL or add to PATH)"
        )
    subprocess.run(
        [
            codeql, "database", "create", str(db),
            "--overwrite", "-l", "teal", "-s", str(src),
            f"--search-path={SEARCH_PATH}",
        ],
        check=True,
        capture_output=True,
    )
    return True


def build_all(*, force: bool = False) -> tuple[int, int]:
    """Build every missing fixture DB. Returns ``(built, skipped)``."""
    built = skipped = 0
    for prog in find_fixtures():
        if build_db(prog, force=force):
            built += 1
        else:
            skipped += 1
    return built, skipped


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", action="store_true",
        help="rebuild every DB even if one already exists",
    )
    args = parser.parse_args()
    built, skipped = build_all(force=args.force)
    print(f"built {built}, skipped {skipped}")
