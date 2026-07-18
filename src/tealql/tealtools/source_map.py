"""TEAL <-> high-level source-line map, read off the compiler's annotations.

Puya (and TealScript) emit ``// contract.py:26`` comments through the generated
TEAL, marking which high-level source line produced the ops that follow. This
recovers that map — a TEAL line belongs to the most recent such comment above it
— so an analysis result on a TEAL line can be reported in the DEVELOPER's terms,
and a question asked about a high-level line can be resolved to the TEAL it
compiled to. Optional: raw / hand-written TEAL carries no such comments and yields
an empty map (every consumer degrades to TEAL-line-only). The parser strips inline
comments, so this reads the RAW ``.teal`` text.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# ``// path/to/contract.py:26`` — the trailing source ref a compiler leaves on the
# ops of that source line. Accepts .py / .ts / .algo.ts and dotted names.
_SRC_REF = re.compile(r"//\s*([\w./\-]+\.(?:py|ts))\b(?:\.[\w.]+)?:(\d+)")


def build_source_map(teal_text: str) -> dict[int, tuple[str, int]]:
    """``{teal_line (1-based): (source_file, source_line)}`` — each TEAL line
    mapped to the most recent ``// file.py:N`` annotation at or above it. Empty
    when the source carries no such comments (raw bytecode)."""
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
    """``{(source_file, source_line): [teal_lines]}`` — the inverse of
    :func:`build_source_map`, TEAL lines sorted."""
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


def source_map_for(source_path: str, file: Optional[str] = None
                   ) -> dict[tuple[str, int], tuple[str, int]]:
    """Build a ``{(teal_file, teal_line): (src_file, src_line)}`` map for a
    ``.teal`` file (or a directory of them). Keyed by ``(teal_file, line)`` so
    a directory's programs (e.g. approval + clear) do NOT clobber each other on
    equal line numbers. ``file`` restricts a directory build to one basename.
    Defensive: any read failure yields ``{}``."""
    out: dict[tuple[str, int], tuple[str, int]] = {}
    try:
        p = Path(source_path)
        if p.is_dir():
            for f in sorted(p.rglob("*.teal")):
                if file is not None and f.name != file:
                    continue
                for ln, src in build_source_map(f.read_text(errors="ignore")).items():
                    out[(f.name, ln)] = src
        elif p.exists():
            for ln, src in build_source_map(p.read_text(errors="ignore")).items():
                out[(p.name, ln)] = src
    except Exception:
        pass
    return out
