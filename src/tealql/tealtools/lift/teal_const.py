"""TEAL source loading + template-name recovery for the lift.

HAZARD: this sits on the detector-facing ``_Lifter.build()`` path and must stay
puya-free — hence ``_const_bytes`` returning a neutral encoding-kind string that
:mod:`to_puya_ir` maps to puya's ``AVMBytesEncoding``, instead of importing it here.
"""
from __future__ import annotations

from ..ast.literals import decode_byte_literal

_SRC_CACHE: dict = {}


def _load_src(source: str) -> dict:
    """Map ``basename -> source lines`` from a ``.teal`` file/dir (cached)."""
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
    """Parse a TEAL byte literal -> ``(raw bytes, kind)``, ``kind`` in base16/utf8/base64/base32."""
    return decode_byte_literal(v)
