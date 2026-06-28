"""The IR-layer fund-flow detector vs the SSA-layer one: a guard-precision case
the IR gets right and the SSA gets wrong.

``owner_guard_across_callsub.teal`` is owner-gated (``txn Sender ==
app_global_get("owner"); assert``) with a ``callsub`` between the guard and the
itxn sink. The SSA ``PathPredicateAnalysis`` is context-insensitive across
``callsub`` -- the shared sub has two callers, so the owner predicate is dropped
at its return merge and the flow is reported UNGUARDED (a false positive). The IR
``ir-tainted-fund-flow`` computes dominance within the lifted subroutine, where
the ``InvokeSubroutine`` doesn't break the assert->sink dominance, and correctly
clears it. This pins that contrast (and the IR detector's correctness on it).
"""
import contextlib
import io
from pathlib import Path

import pytest

pytest.importorskip("puya")

from tealtools.ssa import SSAProgram  # noqa: E402
from security import DETECTORS  # noqa: E402

CASE = (Path(__file__).resolve().parent / "benchmark" / "ir-tainted-fund-flow"
        / "safe" / "owner_guard_across_callsub.teal")


def _fires(detector: str) -> int:
    prog = SSAProgram(str(CASE), verbose=False)
    prog.propagate_constants()
    with contextlib.redirect_stdout(io.StringIO()):       # silence puya logging
        return len(DETECTORS[detector](prog).detect())


def test_ir_clears_owner_guard_across_callsub():
    # the IR layer recognises the owner guard despite the intervening callsub
    assert _fires("ir-tainted-fund-flow") == 0


def test_ssa_falsepositives_on_owner_guard_across_callsub():
    # documents the SSA layer's context-insensitivity FP that motivates the IR
    # sibling; if a future change teaches the SSA detector this guard, update this
    # test (the FP going away is a WIN, not a regression).
    assert _fires("tainted-fund-flow") > 0
