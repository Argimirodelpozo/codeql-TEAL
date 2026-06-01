"""Puya-style IR renderer — xgov debugging workspace.

Builds xgov's :class:`~tealtools.ssa.SSAProgram`, runs the passes listed in
:data:`PASSES` (edit that list as we add / debug passes), and renders the
Puya-style SSA IR (:func:`tealtools.experimental_3.puya_ir.render_puya`,
built on the block-argument view) to ``xgov.ssa.ir`` in the repo root.

    python -m tealtools.experimental_3            # render xgov
    python -m tealtools.experimental_3 <other-db> # or some other DB

The default :data:`PASSES` are annotation-only (constants / ranges / byte-
lengths): they decorate the IR with ``const_value`` / ``range`` / ``type``
(which the render inlines / shows as types) without rewiring operands, so the
per-edge ``exit_stack`` the view reads stays consistent with construction.

What NOT to drop into :data:`PASSES` for a faithful view:
  - ``dedup_phis`` — coalesces phis by value-set (merges anti-correlated
    slots, the swap problem);
  - ``materialize_phis`` — clears ``prog.phis``; block-args ARE the out-of-SSA
    and run in its place, pre-materialise.
The copy-prop / CSE passes (``propagate_inputs``, ``propagate_scratch_values``,
``propagate_stack_shuffles``, ``propagate_stable_expressions``) rewire operands
away from the construction-time ``exit_stack`` — add them knowingly.
"""
from __future__ import annotations

import sys
from pathlib import Path

from ..ssa import SSAProgram
from .lift import lift
from .transforms import (
    collapse_dispatch, eliminate_dead_ops, simplify_trivial_phis,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
XGOV_DB = REPO_ROOT / "tests/dbs/xgov-db"
OUT = REPO_ROOT / "xgov.ssa.ir"

#: Passes run before rendering. Edit freely while debugging xgov.
PASSES = [
    "propagate_constants",
    "propagate_scratch_constants",
    "propagate_ranges",
    "propagate_range_arithmetic",   # const->range + arithmetic composition
    "propagate_assert_ranges",      # flow-sensitive guard refinement
    "propagate_byte_lengths",
    "propagate_bytemath_ranges",
    # add passes here as we debug ↓
]


def render(prog: SSAProgram) -> str:
    """Run :data:`PASSES` on ``prog`` (in place, idempotent), lift it into the
    Puya-shaped IR model, and render that model."""
    for name in PASSES:
        getattr(prog, name)()
    program = lift(prog)
    collapse_dispatch(program)
    simplify_trivial_phis(program)
    eliminate_dead_ops(program)
    return program.render()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    db = argv[0] if argv else str(XGOV_DB)
    prog = SSAProgram(db, verbose=False)
    text = render(prog)
    header = (f"// puya-style SSA IR of {Path(db).name}\n"
              f"// passes: {', '.join(PASSES) or '(none)'}\n\n")
    OUT.write_text(header + text)
    print(f"{Path(db).name}: {len(text.splitlines())} lines -> {OUT}")
    return 0
