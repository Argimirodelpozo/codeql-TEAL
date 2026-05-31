"""Run every available SSA functional / cleanup pass on a program,
in the canonical order, and return the flat functional rendering.

The canonical pipeline has three logical phases. Within a phase,
pass order is constrained by per-pass docstring prerequisites; the
phases themselves carry the high-level dependencies.

**Phase A — value flow.** Resolve constants and unify equivalent
reads so downstream propagation sees one canonical SSAVar per
distinct value, not one per syntactic read site.

  1. :meth:`SSAProgram.propagate_constants` — ``const_value`` on
     literal-pushing producers (other passes consume it).
  2. :meth:`SSAProgram.propagate_scratch_constants` — same but
     across ``store`` / ``load`` for scratch slots.
  3. :meth:`SSAProgram.propagate_inputs` — unify execution-stable
     reads (``txn``-family, ``global``, ``arg``). Rewires consumers
     to a canonical SSAVar per ``(op, immediates [, stack-key])``.
  4. :meth:`SSAProgram.propagate_scratch_values` — generalises (2)
     to arbitrary SSA values: a load is forwarded to its single
     may-store source when all influencing stores agree.

**Phase B — analytical annotation.** Layer range / type / length
annotations on the unified value flow. Order within the phase is
driven by precondition: integer ranges first (other layers consume
them), then arithmetic composition, then bytes-length, then bytes-
as-bigint.

  5. :meth:`SSAProgram.propagate_ranges` — uint64 ``IntRange`` seeds
     from op tables (boolean comparisons, ``getbyte``, txn enum
     fields, …) plus phi union.
  6. :meth:`SSAProgram.propagate_range_arithmetic` — composes (5)
     through ``+`` / ``-`` / ``*`` / ``/`` / ``%`` with phi re-union.
  7. :meth:`SSAProgram.propagate_byte_lengths` — exact byte_length
     on bytes producers (``itob``, ``concat``, ``sha256``, …) plus
     inverse range constraints from ``btoi`` / ``getbyte`` /
     ``extract_uint*`` / etc. on their bytes inputs.
  8. :meth:`SSAProgram.propagate_bytemath_ranges` — bigint value
     range via Python ints on bytemath ops (``b+``, ``b-``, ``b*``,
     ``b/``, ``b%``) plus the ``itob`` / ``btoi`` bridge between
     uint64 and bytes-bigint value spaces.

**Phase C — structural lowering.** Once every annotation is in
place, simplify the IR for rendering: collapse stack shuffles, CSE
the execution-stable expressions, prune dead pure-op assignments,
inline literal constants, and finally materialise phis (which clears
``prog.phis`` — any pass that iterates it must have already run).

  9. :meth:`SSAProgram.propagate_stack_shuffles` — copy-propagate
     pure shuffles (``dup``, ``swap``, ``frame_dig``, …) into every
     consumer; the shuffle Assignments stay in the IR with
     ``shuffled=True`` so they render as ``// …`` comments.
  10. :meth:`SSAProgram.propagate_stable_expressions` — CSE over the
      execution-stable sub-DAG: a pure op of stable inputs is itself
      stable, so syntactically-equal stable expressions (e.g. two
      ``sha256(txn Sender)``) unify to one canonical value. Runs here,
      after shuffles, so compute ops reach their stable operands
      directly.
  11. :meth:`SSAProgram.cleanup_unused_ssavars` — drop side-effect-
      free Assignments whose every output is now dead (the duplicate
      readers from step 3, the forwarded loads from step 4, and the
      CSE'd duplicates from step 10 are the typical victims).
  12. :meth:`SSAProgram.eliminate_dead_constants` — inline literal
      constants into consumers and drop the now-orphan SSAVars /
      Phis / Assignments.
  13. :meth:`SSAProgram.materialize_phis` — out-of-SSA lowering;
      each live phi becomes a synthetic ``mat_phi_k`` with a copy
      assignment at every contributing leaf's def site.

After all thirteen run, :meth:`SSAProgram.functional` (and
``functional_by_block``, plus :func:`functional_dump` here) give
the most-annotated flat dump the substrate can produce. Every
pass is idempotent — running ``run_all_passes`` twice is a no-op
the second time."""
from __future__ import annotations

import logging
import time
from typing import Optional

from ..ssa import SSAProgram

logger = logging.getLogger("tealtools.passes")


def run_all_passes(prog: SSAProgram) -> SSAProgram:
    """Apply every SSA functional pass in the canonical order.
    Returns the same ``prog`` (mutated in place) for chaining. See
    the module docstring for the per-phase rationale.

    Progress is reported through the ``tealtools`` logger: an
    ``INFO`` line when the pipeline starts and a ``DEBUG`` line with
    the wall-clock time for each pass (CLI ``-v`` / ``-vv``)."""
    passes = [
        # Phase A — value flow.
        ("propagate_constants",         prog.propagate_constants),
        ("propagate_scratch_constants", prog.propagate_scratch_constants),
        ("propagate_inputs",            prog.propagate_inputs),
        ("propagate_scratch_values",    prog.propagate_scratch_values),
        # Phase B — analytical annotation.
        ("propagate_ranges",            prog.propagate_ranges),
        ("propagate_range_arithmetic",  prog.propagate_range_arithmetic),
        ("propagate_byte_lengths",      prog.propagate_byte_lengths),
        ("propagate_bytemath_ranges",   prog.propagate_bytemath_ranges),
        # Phase C — structural lowering.
        ("propagate_stack_shuffles",    prog.propagate_stack_shuffles),
        ("propagate_stable_expressions", prog.propagate_stable_expressions),
        ("cleanup_unused_ssavars",      prog.cleanup_unused_ssavars),
        ("eliminate_dead_constants",    prog.eliminate_dead_constants),
        ("materialize_phis",            prog.materialize_phis),
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
    """Run all SSA passes (idempotent) then return the flat
    functional dump.

    ``by_block=True`` groups assignments by basic block with a
    predecessor/successor header per block.

    ``show_ranges=True`` adds ``/*[V<=hi]*/``-style annotations on
    uint64 SSAVars whose :class:`tealtools.ssa.IntRange` is set.

    ``show_bytes=True`` adds ``/*len=N*/`` / ``/*N<=len<=M*/`` /
    ``/*val=…*/`` annotations on bytes-typed SSAVars whose
    :class:`tealtools.ssa.TealType` carries length or value info.
    Implemented via :mod:`tealtools.render_annotated` as a post-pass
    over the existing functional output, so the substrate renderer
    stays focused on IntRange.
    """
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
