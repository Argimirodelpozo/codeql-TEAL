"""Regression for the dead-``assert 0`` mixed-type join phi (lift bug surfaced by
the mainnet sweep, app_531558171).

The contract destructures a bytes blob at a join (`label8`) reached by several
live `b label8` jumps -- each carrying a byte array -- AND by the dead
fall-through of `label9: int 0; assert` (an always-failing reject). That dead
predecessor contributed a *uint64* (a dispatch selector) to the join's phi,
making it mixed-AVM-type (3×bytes + 1×uint64). The typed lift couldn't reconcile
it, dropped the phi, and emitted operand-less `extract` / `extract_uint64`
intrinsics that Puya's MIR backend rejects ("l-stack too small for extract").

`_prune_dead_assert_edges` removes the dead `assert 0` fall-through edge into the
join before block-args lowering and rebuilds the join's phis from the surviving
(all-bytes) predecessors, so the join is the clean merge it is at runtime; the
now-terminal `assert 0` block lifts to `Fail` (it aborts there) rather than a
`ProgramExit` of a non-uint64 stack top.
"""
from pathlib import Path

import pytest

pytest.importorskip("puya")

from tealtools.ssa import SSAProgram  # noqa: E402
from tealtools.WIP_lift2puyaIR import pre_ir as P  # noqa: E402
from tealtools.WIP_lift2puyaIR.lift import _Lifter  # noqa: E402

CONTRACT = (Path(__file__).resolve().parent / "experimental_IR_lift" / "explorer"
            / "app_531558171" / "app_531558171.teal")

# intrinsics that consume >=1 stack operand; an instance with no args is the
# dropped-survivor symptom this fix prevents.
_CONSUMERS = {"extract", "extract_uint64", "extract_uint32", "extract_uint16",
              "getbyte", "getbit", "substring"}


def _intrinsic(op):
    if isinstance(op, P.Assignment) and isinstance(op.source, P.Intrinsic):
        return op.source
    if isinstance(op, P.IntrinsicOp) and isinstance(op.intrinsic, P.Intrinsic):
        return op.intrinsic
    return None


def test_assert_false_join_lifts_without_orphan_extract():
    prog = SSAProgram(str(CONTRACT), verbose=False)
    prog.propagate_constants()
    lifted = _Lifter(prog).build()                      # must not raise

    orphans = []
    for sub in [lifted.main, *lifted.subroutines]:
        for bb in sub.body:
            for op in bb.ops:
                intr = _intrinsic(op)
                if intr is not None and intr.op in _CONSUMERS and not intr.args:
                    orphans.append((bb.id, intr.op, intr.immediates))
    assert not orphans, (
        "operand-less operand-consuming intrinsic(s) survived the lift -- the "
        f"dead-assert join phi was dropped again: {orphans}")
