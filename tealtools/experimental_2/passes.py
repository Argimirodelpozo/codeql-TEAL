"""Run every available SSA functional / cleanup pass on a program,
in the canonical order, and return the flat functional rendering.

Pass order matters — each pass's docstring in :mod:`tealtools.ssa`
specifies prerequisites. The order here matches them:

1. :meth:`SSAProgram.propagate_constants` — set ``const_value`` on
   SSAVars whose producer is a literal-pushing op. Other passes
   reference these as a precondition.
2. :meth:`SSAProgram.propagate_scratch_constants` — separately
   propagates constants through ``store`` / ``load`` for scratch
   slots. Runs after ``propagate_constants`` (lazy-trips it if not
   already run). Idempotent.
3. :meth:`SSAProgram.propagate_ranges` — integer range propagation
   for SSAVars (lower/upper bounds), useful for downstream analyses
   that care about bounds (overflow checks, box-size estimates, ...).
4. :meth:`SSAProgram.propagate_stack_shuffles` — pure stack-shuffle
   ops (``frame_dig``, ``dup``, ``swap``, ...) have their outputs
   copy-propagated into every consumer; the shuffles themselves are
   marked ``shuffled=True`` and rendered as ``// ...`` comments in
   the functional dump. **Must** run before ``materialize_phis``
   (the docstring spells out why — phi args are a different newtype
   pre-materialisation).
5. :meth:`SSAProgram.eliminate_dead_constants` — inlines literal
   constants into every consumer and drops the now-orphan SSAVars
   / Phi nodes / Assignments. Aggressive cleanup; runs last in the
   pre-materialise group.
6. :meth:`SSAProgram.materialize_phis` — out-of-SSA lowering: each
   live phi becomes a synthetic ``mat_phi_k`` "mutable variable"
   with a copy assignment inserted at each leaf's def site.

After all six run, :meth:`SSAProgram.functional` (and
``functional_by_block``) give the cleanest flat dump the substrate
can produce. Every pass is idempotent — running ``run_all_passes``
twice is a no-op the second time."""
from __future__ import annotations

from typing import Optional

from ..ssa import SSAProgram


def run_all_passes(prog: SSAProgram, *, verbose: bool = False) -> SSAProgram:
    """Apply every SSA functional pass in the canonical order.
    Returns the same ``prog`` (mutated in place) for chaining."""
    passes = [
        ("propagate_constants",        prog.propagate_constants),
        ("propagate_scratch_constants", prog.propagate_scratch_constants),
        ("propagate_ranges",            prog.propagate_ranges),
        ("propagate_stack_shuffles",    prog.propagate_stack_shuffles),
        ("eliminate_dead_constants",    prog.eliminate_dead_constants),
        ("materialize_phis",            prog.materialize_phis),
    ]
    for name, fn in passes:
        if verbose:
            import time
            t0 = time.perf_counter()
            fn()
            print(f"  {name}: {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)
        else:
            fn()
    return prog


def functional_dump(
    prog: SSAProgram,
    *,
    file: Optional[str] = None,
    line_range: Optional[tuple[int, int]] = None,
    by_block: bool = False,
    show_ranges: bool = False,
) -> str:
    """Run all SSA passes (idempotent) then return the flat
    functional dump. ``by_block=True`` groups assignments by BB
    with a predecessor/successor header per block."""
    run_all_passes(prog)
    if by_block:
        return prog.functional_by_block(file=file, show_ranges=show_ranges)
    return prog.functional(file=file, line_range=line_range, show_ranges=show_ranges)
