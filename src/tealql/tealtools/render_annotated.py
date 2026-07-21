"""Post-pass annotations for the functional dump.

The substrate's :meth:`tealql.tealtools.ssa.SSAProgram.functional` knows
how to inline :class:`tealql.tealtools.ssa.IntRange` comments on uint64
SSAVars when called with ``show_ranges=True``. It does *not* know
about the bytes-side annotations laid down by the analytical-phase
passes — :attr:`TealType.byte_length`,
:attr:`TealType.byte_length_range`, :attr:`TealType.int_value_range`.

Rather than teach the substrate renderer about every bytes
annotation (and grow its kwargs surface every time a new pass
ships), this module post-processes a functional dump: it walks the
program's bytes-typed SSAVars, builds an identifier→comment table,
and substitutes the comment after each occurrence of the
identifier in the dump.

Used by :func:`tealql.tealtools.passes.functional_dump`
when called with ``show_bytes=True``.
"""
from __future__ import annotations

import re

from .ssa import SSAProgram, TealType


def _len_annot(t: TealType) -> str | None:
    """Human-readable byte_length / byte_length_range annotation.
    Returns ``None`` when the type carries no length info."""
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
    """Human-readable int_value_range annotation. Bigints longer
    than ``bigint_str_cap`` digits collapse to ``<N-bit>`` so the
    dump line stays readable."""
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
    """Inject ``/*len=… val=…*/`` comments after every occurrence of
    a bytes-typed SSAVar identifier in ``body``. Idempotent for the
    same ``prog`` state — running twice produces the same string.

    The annotation only appears for SSAVars whose
    :class:`TealType` carries at least one of ``byte_length``,
    ``byte_length_range``, or ``int_value_range``. Identifier
    matching is word-bounded so ``V#1@L10`` doesn't capture
    ``V#1@L100``.
    """
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
        # Genuinely idempotent: the identifier regex's lookahead only rejects
        # trailing identifier characters, so a SECOND pass re-matched an
        # already-annotated occurrence and appended a duplicate comment. Skip
        # when this occurrence is already followed by one.
        rest = match.string[match.end():]
        if rest.startswith(" /*") or rest.startswith("/*"):
            return ident
        return f"{ident} {annot}"

    return _IDENTIFIER_RE.sub(_sub, body)
