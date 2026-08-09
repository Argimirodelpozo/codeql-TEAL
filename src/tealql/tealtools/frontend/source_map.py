"""TEAL <-> high-level source-line map, read off compiler ``// contract.py:26``
annotations: a TEAL line belongs to the most recent such comment above it.

Optional — raw / hand-written TEAL carries no such comments and yields an empty
map, so consumers degrade to TEAL lines only. Reads the RAW ``.teal`` text,
since the parser strips comments.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# The trailing source ref a compiler leaves on the ops of that source line;
# accepts .py / .ts / .algo.ts and dotted names.
_SRC_REF = re.compile(r"//\s*([\w./\-]+\.(?:py|ts))\b(?:\.[\w.]+)?:(\d+)")


def build_source_map(teal_text: str) -> dict[int, tuple[str, int]]:
    """``{teal_line (1-based): (source_file, source_line)}`` — each TEAL line mapped
    to the most recent ``// file.py:N`` annotation at or above it."""
    fwd: dict[int, tuple[str, int]] = {}
    cur: Optional[tuple[str, int]] = None
    for i, line in enumerate(teal_text.splitlines(), 1):
        m = _SRC_REF.search(line)
        if m:
            cur = (m.group(1), int(m.group(2)))
        if cur is not None:
            fwd[i] = cur
    return fwd


def reverse_source_map(fwd: dict[int, tuple[str, int]]
                       ) -> dict[tuple[str, int], list[int]]:
    """Inverse of :func:`build_source_map`: ``{(source_file, source_line):
    [teal_lines]}`` (sorted)."""
    rev: dict[tuple[str, int], list[int]] = {}
    for tl, src in fwd.items():
        rev.setdefault(src, []).append(tl)
    for v in rev.values():
        v.sort()
    return rev


def reverse_file_source_map(fwd: dict[tuple[str, int], tuple[str, int]]
                            ) -> dict[tuple[str, int], list[tuple[str, int]]]:
    """Inverse of a ``(teal_file, teal_line) -> (src_file, src_line)`` map:
    ``{(src_file, src_line): [(teal_file, teal_line), …]}`` (sorted)."""
    rev: dict[tuple[str, int], list[tuple[str, int]]] = {}
    for tl, src in fwd.items():
        rev.setdefault(src, []).append(tl)
    for v in rev.values():
        v.sort()
    return rev


def source_map_for(source, file: Optional[str] = None
                   ) -> dict[tuple[str, int], tuple[str, int]]:
    """``{(teal_file, teal_line): (src_file, src_line)}`` for a ``.teal`` file or a
    directory of them — keyed by file so a directory's programs (approval + clear)
    do NOT clobber each other on equal line numbers; any read failure yields ``{}``."""
    from .sources import ProgramSources

    bundle = source if isinstance(source, ProgramSources) else getattr(source, "sources", None)
    try:
        if not isinstance(bundle, ProgramSources):
            bundle = ProgramSources.load(source)
    except Exception:
        return {}

    selected = list(bundle.files)
    if file is not None:
        exact = [unit for unit in selected if unit.name == file]
        if exact:
            selected = exact
        else:
            # Compatibility for a unique legacy basename; ambiguous nested
            # basenames deliberately match nothing rather than clobbering.
            matches = [unit for unit in selected if Path(unit.name).name == file]
            selected = matches if len(matches) == 1 else []

    out: dict[tuple[str, int], tuple[str, int]] = {}
    for unit in selected:
        for line, src in build_source_map(unit.text()).items():
            out[(unit.name, line)] = src
    return out
