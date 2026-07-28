"""Target resolution for the tealql CLI — a target is a single ``.teal`` file or a
directory containing one or more, which the pipeline reads directly.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..errors import TargetError, TargetNotFoundError

logger = logging.getLogger("tealql.tealtools._utils.targets")


def _discover_teal_files(path: Path) -> list[Path]:
    """The ``.teal`` files implied by ``path`` (a directory is walked recursively);
    raises if the file isn't ``.teal`` or the directory holds none."""
    if path.is_file():
        if path.suffix != ".teal":
            raise TargetError(f"{path}: not a .teal file")
        return [path.resolve()]
    teal = sorted(p.resolve() for p in path.rglob("*.teal"))
    if not teal:
        raise TargetNotFoundError(f"no .teal files found under {path}")
    return teal


def resolve_target(target: str | Path) -> Path:
    """Validate a user-supplied target and return its path, raising
    :class:`~tealql.tealtools.errors.TargetError` /
    :class:`~tealql.tealtools.errors.TargetNotFoundError` if it doesn't exist or
    holds no ``.teal``."""
    path = Path(target).resolve()
    if not path.exists():
        raise TargetNotFoundError(f"target does not exist: {target}")
    logger.info("resolving target: %s", path)
    teal_files = _discover_teal_files(path)   # validates: raises if none / non-teal
    logger.info("target is %d .teal file(s): %s", len(teal_files), path)
    return path
