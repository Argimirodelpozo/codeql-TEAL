"""Loop cost and iteration bounds (:mod:`tealql.tealtools.pathgraph`).

The bounds are UPPER limits on what the AVM permits, never trip counts — a loop
bounded at 700 usually runs three times. What is pinned here is that the two
ceilings are computed from the right things: puya's per-op costs, and the
cheapest cycle through the body (an upper bound on ITERATIONS needs the lower
bound on cost per iteration).
"""
from __future__ import annotations

from tealql.tealtools.pathgraph import (
    APP_OPCODE_BUDGET,
    analyze_loops,
    op_cost,
)
from tealql.tealtools.ssa import SSAProgram

_COUNT_LOOP = ("#pragma version 10\nint 0\nstore 0\n"
               "loop:\nload 0\nint 5\n<\nbz done\n"
               "{body}"
               "load 0\nint 1\n+\nstore 0\nb loop\n"
               "done:\nint 1\nreturn\n")


def _loops(src):
    return analyze_loops(SSAProgram.from_text(src, strict=False))


def test_cost_comes_from_the_langspec_not_a_step_count():
    """An iteration's cost is opcode BUDGET, not instructions: `sha256` alone is
    35. Counting steps would over-estimate how many times a loop can run, which
    is the unsound direction for a bound."""
    assert op_cost("+") == 1
    assert op_cost("sha256") == 35
    assert op_cost("ed25519verify") == 1900
    assert op_cost("no_such_opcode_in_this_build") == 1   # floor, never 0

    cheap = _loops(_COUNT_LOOP.format(body=""))[0]
    pricey = _loops(_COUNT_LOOP.format(body="byte 0x00\nsha256\npop\n"))[0]
    assert pricey.min_iteration_cost == cheap.min_iteration_cost + 35 + 2
    # Costlier body, strictly fewer permitted iterations.
    assert pricey.max_iterations < cheap.max_iterations
    assert cheap.max_iterations == APP_OPCODE_BUDGET // cheap.min_iteration_cost


def test_stack_ceiling_applies_only_to_a_net_POSITIVE_loop():
    """A loop that grows the stack dies at the depth cap; a net-zero one — the
    common case — is bounded by budget alone, and must not be reported as
    stack-bounded."""
    flat = _loops(_COUNT_LOOP.format(body=""))[0]
    assert flat.stack_delta == 0
    assert flat.stack_bound is None
    assert flat.bound_reason == "budget"

    grow = _loops("#pragma version 10\nloop:\nint 1\ntxn NumAppArgs\nbnz loop\n"
                  "int 1\nreturn\n")[0]
    assert grow.stack_delta > 0
    assert grow.stack_bound is not None
    # Whichever ceiling binds first is the answer.
    assert grow.max_iterations == min(grow.budget_bound, grow.stack_bound)


def test_one_loop_per_header_and_no_loop_when_there_is_none():
    """Two `continue` edges close ONE loop, not two — back edges are grouped by
    header. And straight-line code has none."""
    two_continues = _loops(
        "#pragma version 10\nint 0\nstore 0\n"
        "loop:\nload 0\nint 9\n<\nbz done\n"
        "txn NumAppArgs\nbnz loop\n"          # first back edge
        "load 0\nint 1\n+\nstore 0\nb loop\n"  # second back edge
        "done:\nint 1\nreturn\n")
    assert len(two_continues) == 1
    assert len(two_continues[0].back_edges) == 2

    assert _loops("#pragma version 10\nint 1\nreturn\n") == []
