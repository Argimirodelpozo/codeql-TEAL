"""Post-pass bytes annotations for the functional dump — the substrate renderer
inlines only :class:`IntRange` comments, so the bytes-side annotations
(``byte_length`` / ``byte_length_range`` / ``int_value_range``) are substituted
into the rendered text here instead of growing its kwargs surface.
"""
from __future__ import annotations

import re

from ..ssa import SSAProgram, TealType


def _len_annot(t: TealType) -> str | None:
    """Human-readable byte_length / byte_length_range annotation, or ``None``."""
    if t.byte_length is not None:
        return f"len={t.byte_length}"
    r = t.byte_length_range
    if r is None:
        return None
    if r.lo == r.hi:
        return f"len={r.lo}"
    if r.lo == 0:
        return f"len<={r.hi}"
    return f"{r.lo}<=len<={r.hi}"


def _ivr_annot(t: TealType, *, bigint_str_cap: int = 40) -> str | None:
    """Human-readable int_value_range annotation, bigints over ``bigint_str_cap``
    digits collapsed to ``<N-bit>``."""
    r = t.int_value_range
    if r is None:
        return None

    def _short(n: int) -> str:
        s = str(n)
        if len(s) <= bigint_str_cap:
            return s
        return f"<{n.bit_length()}-bit>"

    if r.lo == r.hi:
        return f"val={_short(r.lo)}"
    return f"val∈[{_short(r.lo)}..{_short(r.hi)}]"


_IDENTIFIER_RE = re.compile(r"V#\d+@L\d+(?![\dA-Za-z_])")


def annotate_bytes_inline(prog: SSAProgram, body: str) -> str:
    """Inject ``/*len=… val=…*/`` after every occurrence in ``body`` of a bytes-typed
    SSAVar identifier that carries length or value info; idempotent."""
    annot_for: dict[str, str] = {}
    for v in prog.vars.values():
        t = v.type
        if t is None or t.kind != "bytes":
            continue
        parts = []
        la = _len_annot(t)
        if la:
            parts.append(la)
        ia = _ivr_annot(t)
        if ia:
            parts.append(ia)
        if not parts:
            continue
        annot_for[v.identifier] = "/*" + " ".join(parts) + "*/"

    if not annot_for:
        return body

    def _sub(match: re.Match) -> str:
        ident = match.group(0)
        annot = annot_for.get(ident)
        if annot is None:
            return ident
        # The regex lookahead only rejects trailing identifier characters, so a
        # second pass would re-match an annotated occurrence and append a
        # duplicate; skip when one is already there.
        rest = match.string[match.end():]
        if rest.startswith(" /*") or rest.startswith("/*"):
            return ident
        return f"{ident} {annot}"

    return _IDENTIFIER_RE.sub(_sub, body)
