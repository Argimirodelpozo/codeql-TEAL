"""Presentation views built from an isolated derived SSA program."""
from __future__ import annotations

from typing import Optional

from .context import DerivedProfile, derived_program
from ..ssa import SSAProgram


def functional_dump(
    prog: SSAProgram,
    *,
    file: Optional[str] = None,
    line_range: Optional[tuple[int, int]] = None,
    by_block: bool = False,
    show_ranges: bool = False,
    show_bytes: bool = False,
) -> str:
    """Render a simplified private view without changing ``prog``."""
    view = derived_program(prog, DerivedProfile.PRESENTATION)
    if by_block:
        out = view.functional_by_block(file=file, show_ranges=show_ranges)
    else:
        out = view.functional(
            file=file, line_range=line_range, show_ranges=show_ranges,
        )
    if show_bytes:
        from ..viz.annotated import annotate_bytes_inline
        out = annotate_bytes_inline(view, out)
    return out
