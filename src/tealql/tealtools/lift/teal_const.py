"""TEAL source loading + template-name recovery for the lift.

HAZARD: this sits on the detector-facing ``_Lifter.build()`` path and must stay
puya-free — hence ``_const_bytes`` returning a neutral encoding-kind string that
:mod:`to_puya_ir` maps to puya's ``AVMBytesEncoding``, instead of importing it here.
"""
from __future__ import annotations

from ..ast.literals import decode_byte_literal

def _load_src(source) -> dict:
    """Map canonical file identity -> RAW source lines from a snapshot.

    ``ProgramSources`` is the normal path. A filesystem argument remains for
    compatibility, but is captured for this call rather than entering a global
    path-only cache that could return bytes from an earlier file version.
    """
    from ..frontend.sources import ProgramSources

    bundle = source if isinstance(source, ProgramSources) else getattr(source, "sources", None)
    if not isinstance(bundle, ProgramSources):
        try:
            bundle = ProgramSources.load(source)
        except Exception:
            return {}
    return {name: list(lines) for name, lines in bundle.line_map().items()}


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
