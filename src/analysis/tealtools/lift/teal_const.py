"""TEAL source loading + template-name recovery for the lift.

The pure TEAL-literal / operand parsing this module used to do now lives in
:mod:`tealtools.ast.literals` (puya-free). What remains is lift-specific: the
cached source loader (``_load_src``), dropped-template-name recovery
(``_tmpl_name``), and a thin ``_const_bytes`` wrapper that tags the decoded
bytes with puya's ``AVMBytesEncoding``.
"""
from __future__ import annotations

from puya.ir.types_ import AVMBytesEncoding

from ..ast.literals import decode_byte_literal

_SRC_CACHE: dict = {}

# Neutral encoding-kind name (from ast.literals) -> puya's enum.
_AVM_ENCODING = {
    "base16": AVMBytesEncoding.base16,
    "utf8": AVMBytesEncoding.utf8,
    "base64": AVMBytesEncoding.base64,
    "base32": AVMBytesEncoding.base32,
}


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
    """Parse a TEAL byte literal -> ``(raw bytes, AVMBytesEncoding)``. Thin
    wrapper over :func:`tealtools.ast.literals.decode_byte_literal` that tags
    the result with puya's encoding enum."""
    raw, kind = decode_byte_literal(v)
    return raw, _AVM_ENCODING[kind]
