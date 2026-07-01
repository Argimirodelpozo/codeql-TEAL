"""TEAL source loading + template-name recovery for the lift.

The pure TEAL-literal / operand parsing this module used to do now lives in
:mod:`tealtools.ast.literals` (puya-free). What remains is lift-specific: the
cached source loader (``_load_src``), dropped-template-name recovery
(``_tmpl_name``), and a thin ``_const_bytes`` wrapper over the literal decoder.

This module is deliberately **puya-free** — it sits on the detector-facing
``_Lifter.build()`` path, so importing it must not drag in the puya package
(only the final ``to_puya_ir`` lowering needs puya). ``_const_bytes`` returns
a neutral encoding-kind string; ``to_puya_ir`` maps it to puya's
``AVMBytesEncoding`` enum where the IR is actually built.
"""
from __future__ import annotations

from ..ast.literals import decode_byte_literal

_SRC_CACHE: dict = {}


def _load_src(source: str) -> dict:
    """Map ``basename -> source lines`` from a ``.teal`` file/dir (cached).
    Delegates to the shared graph-layer resolver so the lift reads the same
    source the graph build does."""
    if source in _SRC_CACHE:
        return _SRC_CACHE[source]
    from ..graph import _load_source_bytes
    m = {
        bn: data.decode("utf-8", "replace").splitlines()
        for bn, data in _load_source_bytes(source).items()
    }
    _SRC_CACHE[source] = m
    return m


def _tmpl_name(src_map: dict, line: int) -> str:
    """Recover the template-var operand (``TMPL_X``) at ``line`` from source."""
    if line and len(src_map) == 1:
        lines = next(iter(src_map.values()))
        if 1 <= line <= len(lines):
            parts = lines[line - 1].split("//")[0].strip().split(None, 1)
            if len(parts) == 2 and parts[1].strip():
                return parts[1].strip()
    return f"TMPL_anon_{line}" if line else "TMPL_anon"


def _const_bytes(v: str):
    """Parse a TEAL byte literal -> ``(raw bytes, kind)`` where ``kind`` is a
    neutral encoding-kind string (``"base16"`` / ``"utf8"`` / ``"base64"`` /
    ``"base32"``). Kept puya-free (see the module docstring); ``to_puya_ir``
    maps ``kind`` to puya's ``AVMBytesEncoding``. Thin wrapper over
    :func:`tealtools.ast.literals.decode_byte_literal`."""
    return decode_byte_literal(v)
