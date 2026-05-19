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

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

DEFAULT_CACHE = Path(
    os.environ.get("TEALQL_DB_CACHE",
                   Path.home() / ".cache" / "tealql" / "dbs")
)


# ---------------------------------------------------------------------------
# CodeQL invocation helpers
# ---------------------------------------------------------------------------


def _codeql() -> str:
    cmd = os.environ.get("CODEQL") or shutil.which("codeql")
    if cmd is None:
        raise RuntimeError(
            "codeql binary not found (set $CODEQL or add to PATH)"
        )
    return cmd


def _search_path() -> Optional[str]:
    """Locate the bundled ``.codeql-extractors`` dir by walking parents
    of this file. Returns ``None`` if not found (caller falls back to
    CodeQL's own search path)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / ".codeql-extractors"
        if candidate.exists():
            return str(candidate)
    return None


def _dir_signature(teal_files: list[Path]) -> str:
    """Stable hash of ``(basename, content)`` for every .teal file.
    Survives moves of the parent dir as long as basenames and bytes
    don't change."""
    h = hashlib.sha256()
    for f in sorted(teal_files, key=lambda p: p.name):
        h.update(f.name.encode())
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:16]


def build_db_for_dir(
    teal_files: list[Path],
    *,
    cache_root: Path = DEFAULT_CACHE,
    force_rebuild: bool = False,
    verbose: bool = False,
) -> Path:
    """Build (or re-use) a CodeQL DB from ``teal_files``. The files
    must all live in the same logical group; the cache key hashes
    basenames and contents.

    The build stages each .teal under a per-cache-entry ``src/`` dir
    (codeql's extractor doesn't follow symlinks), then runs
    ``codeql database create``. With a warm cache this is a no-op.
    """
    if not teal_files:
        raise ValueError("teal_files is empty")
    sig = _dir_signature(teal_files)
    cache_dir = cache_root / sig
    db = cache_dir / "db"
    if not force_rebuild and (db / "codeql-database.yml").exists():
        return db
    cache_dir.mkdir(parents=True, exist_ok=True)
    src = cache_dir / "src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir()
    for f in teal_files:
        shutil.copy2(f, src / f.name)
    cmd = [_codeql(), "database", "create", str(db),
           "--overwrite", "-l", "teal", "-s", str(src)]
    sp = _search_path()
    if sp is not None:
        cmd.append(f"--search-path={sp}")
    if verbose:
        print(f"[tealql] building DB for {sig} ({len(teal_files)} files)...")
    subprocess.run(cmd, check=True, capture_output=not verbose)
    return db


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
    cache_root: Path = DEFAULT_CACHE,
    force_rebuild: bool = False,
    verbose: bool = False,
) -> Path:
    """Resolve a user-supplied path to a CodeQL DB.

    If ``target`` already points at a DB, it's returned as-is.
    Otherwise ``.teal`` files are discovered under ``target`` (which
    may be a single file or a directory tree) and a DB is built or
    reused from the cache.
    """
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    if is_codeql_db(path):
        if force_rebuild and verbose:
            print(f"[tealql] --force-rebuild ignored: {path} is a "
                  f"pre-built DB, not a source tree")
        return path
    teal_files = _discover_teal_files(path)
    return build_db_for_dir(
        teal_files,
        cache_root=cache_root,
        force_rebuild=force_rebuild,
        verbose=verbose,
    )
