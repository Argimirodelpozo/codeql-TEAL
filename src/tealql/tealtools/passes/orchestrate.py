"""Chain every SSA functional / cleanup pass in the canonical order and render.

HAZARD: every pass must be idempotent — callers re-run the pipeline freely, so a
pass that accumulates on a second run corrupts the annotations. Phase order is a
precondition chain, not a preference: value flow (A) must canonicalise SSAVars
before the annotation layers (B) attach anything to them, and structural cleanup
(C) must come last or it drops assignments the annotators still need."""
from __future__ import annotations

import logging
import time
from typing import Optional

from ..ssa import SSAProgram

logger = logging.getLogger("tealql.tealtools.passes")


def run_all_passes(prog: SSAProgram) -> SSAProgram:
    """Apply every SSA functional pass in canonical order; mutates and returns ``prog``."""
    passes = [
        # Phase A — value flow.
        ("propagate_constants",         prog.propagate_constants),
        ("propagate_scratch_constants", prog.propagate_scratch_constants),
        ("propagate_inputs",            prog.propagate_inputs),
        ("propagate_scratch_values",    prog.propagate_scratch_values),
        # Phase B — analytical annotation.
        ("propagate_ranges",            prog.propagate_ranges),
        ("propagate_range_arithmetic",  prog.propagate_range_arithmetic),
        ("propagate_assert_ranges",     prog.propagate_assert_ranges),
        ("propagate_byte_lengths",      prog.propagate_byte_lengths),
        ("propagate_bytemath_ranges",   prog.propagate_bytemath_ranges),
        # Phase C — structural cleanup.
        ("propagate_stack_shuffles",    prog.propagate_stack_shuffles),
        ("cleanup_unused_ssavars",      prog.cleanup_unused_ssavars),
    ]
    logger.info("running SSA pass pipeline (%d passes)", len(passes))
    for name, fn in passes:
        t0 = time.perf_counter()
        fn()
        logger.debug("pass %s: %.0fms", name, (time.perf_counter() - t0) * 1000)
    return prog


def functional_dump(
    prog: SSAProgram,
    *,
    file: Optional[str] = None,
    line_range: Optional[tuple[int, int]] = None,
    by_block: bool = False,
    show_ranges: bool = False,
    show_bytes: bool = False,
) -> str:
    """Run all SSA passes, then return the functional dump with the requested annotations."""
    run_all_passes(prog)
    if by_block:
        out = prog.functional_by_block(file=file, show_ranges=show_ranges)
    else:
        out = prog.functional(
            file=file, line_range=line_range, show_ranges=show_ranges,
        )
    if show_bytes:
        from ..render_annotated import annotate_bytes_inline
        out = annotate_bytes_inline(prog, out)
    return out
