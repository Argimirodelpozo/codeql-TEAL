"""Target resolution and CodeQL DB building for the tealql CLI.

A *target* is whatever the user points at on the command line:

* an existing CodeQL DB directory (contains ``codeql-database.yml``),
* a single ``.teal`` file, or
* a directory containing one or more ``.teal`` files.

:func:`resolve_target` collapses all three forms to a DB path on disk,
building (and caching) a DB on the fly when the input is raw source.
DBs are content-addressed under ``~/.cache/tealql/dbs/<sha>/db/`` (set
``TEALQL_DB_CACHE`` to override the root), so re-running on the same
inputs reuses prior builds without re-extracting.

The CodeQL extractor bundled with the repo is auto-discovered by
walking parents for ``.codeql-extractors/``; no environment setup is
needed in a fresh checkout.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("tealtools.targets")

# Legacy default location for a per-target DB cache. No CodeQL DB is built any
# more — the pipeline reconstructs straight from raw ``.teal`` — but the CLI
# still surfaces a ``--db-cache`` flag / ``debug cache`` subcommand against this
# path, so the constant is kept.
DEFAULT_CACHE = Path(
    os.environ.get("TEALQL_DB_CACHE", Path.home() / ".cache" / "tealql" / "dbs")
)


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


def is_codeql_db(path: Path) -> bool:
    """True if ``path`` looks like an existing CodeQL DB directory."""
    return path.is_dir() and (path / "codeql-database.yml").exists()


def _discover_teal_files(path: Path) -> list[Path]:
    """Return the .teal files implied by ``path``. A file ``foo.teal``
    yields ``[foo.teal]``; a dir is walked recursively. The returned
    list is grouped under a single DB build."""
    if path.is_file():
        if path.suffix != ".teal":
            raise ValueError(f"{path}: not a .teal file")
        return [path.resolve()]
    teal = sorted(p.resolve() for p in path.rglob("*.teal"))
    if not teal:
        raise FileNotFoundError(f"no .teal files found under {path}")
    return teal


def resolve_target(
    target: str | Path,
    *,
    cache_root: Path | None = None,
    force_rebuild: bool = False,
) -> Path:
    """Resolve a user-supplied path to something the pipeline can read.

    A pre-built CodeQL database directory is returned as-is (its ``src.zip`` is
    read by the pure-Python graph backend); a raw ``.teal`` file or a directory
    of ``.teal`` files is likewise returned as-is — ``SSAProgram`` / ``load_graph``
    reconstruct straight from the source, so there is no DB to build. Raises if
    the target doesn't exist, or is a directory / file with no ``.teal``.

    ``cache_root`` / ``force_rebuild`` are accepted for CLI backward
    compatibility and ignored (nothing is built or cached).
    """
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    logger.info("resolving target: %s", path)
    if is_codeql_db(path):
        logger.info("target is a pre-built CodeQL DB: %s", path)
        return path
    teal_files = _discover_teal_files(path)   # validates: raises if none / non-teal
    logger.info("target is %d .teal file(s): %s", len(teal_files), path)
    return path
