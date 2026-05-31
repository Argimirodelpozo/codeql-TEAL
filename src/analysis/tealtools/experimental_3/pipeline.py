"""Block-argument renderer — xgov debugging workspace.

Builds xgov's :class:`~tealtools.ssa.SSAProgram`, runs the passes listed in
:data:`PASSES` (edit that list as we add / debug passes), and renders the
block-argument out-of-SSA view (:func:`tealtools.block_args.to_block_args`) to
``xgov_block_args.txt`` in the repo root.

    python -m tealtools.experimental_3            # render xgov
    python -m tealtools.experimental_3 <other-db> # or some other DB

What NOT to drop into :data:`PASSES` for a *faithful* executable view:
  - ``dedup_phis`` — coalesces phis by value-set, merging anti-correlated
    slots (the swap problem);
  - ``materialize_phis`` — clears ``prog.phis``; block-args ARE the out-of-SSA
    lowering and run in its place, on the pre-materialisation IR.
The copy-prop / CSE passes (``propagate_inputs``, ``propagate_scratch_values``,
``propagate_stack_shuffles``, ``propagate_stable_expressions``) rewire operands
away from the construction-time ``exit_stack`` the view reads — add them
knowingly. The default set is annotation-only (constants), which the render
inlines and which keeps the view consistent with construction.
"""
from __future__ import annotations

import sys
from pathlib import Path

from ..block_args import to_block_args
from ..ssa import SSAProgram

REPO_ROOT = Path(__file__).resolve().parents[4]
XGOV_DB = REPO_ROOT / "tests/dbs/xgov-db"
OUT = REPO_ROOT / "xgov_block_args.txt"

#: Passes run before rendering. Edit freely while debugging xgov.
PASSES = [
    "propagate_constants",
    "propagate_scratch_constants",
    # add passes here as we debug ↓
]


def render(prog: SSAProgram) -> str:
    """Run :data:`PASSES` on ``prog`` (in place, idempotent) and return the
    block-argument render."""
    for name in PASSES:
        getattr(prog, name)()
    return to_block_args(prog).render()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    db = argv[0] if argv else str(XGOV_DB)
    prog = SSAProgram(db, verbose=False)
    text = render(prog)
    header = (f"# block-args render of {Path(db).name}\n"
              f"# passes: {', '.join(PASSES) or '(none)'}\n\n")
    OUT.write_text(header + text)
    print(f"{Path(db).name}: {len(text.splitlines())} lines -> {OUT}")
    return 0
