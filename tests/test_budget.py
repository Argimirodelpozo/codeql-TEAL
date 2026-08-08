"""Loop cost and iteration bounds (:mod:`tealql.tealtools.budget.loop_bounds`).

The bounds are UPPER limits on what the AVM permits, never trip counts — a loop
bounded at 700 usually runs three times. What is pinned here is that the two
ceilings are computed from the right things: puya's per-op costs, and the
cheapest cycle through the body (an upper bound on ITERATIONS needs the lower
bound on cost per iteration).
"""
from __future__ import annotations

from tealql.tealtools.budget import (
    APP_OPCODE_BUDGET,
    analyze_loops,
    block_cost,
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


def test_mandatory_prefix_is_subtracted_from_the_loop_budget():
    """Blocks that STRICTLY DOMINATE the header run on every path reaching it,
    so their cost is spent before the first iteration and the loop never gets
    the full 700.

    Counting a dominator once is the sound direction: one that is itself inside
    another loop runs MORE than once, which only spends more budget and lowers
    the bound further."""
    from tealql.tealtools.cfg import CFG

    # An expensive but unconditional preamble: `sha256` costs 35 and dominates
    # the loop header, so the loop cannot have all 700.
    src = ("#pragma version 10\n"
           "byte 0x00\nsha256\nsha256\nsha256\npop\n"      # 105 budget, mandatory
           "int 0\nstore 0\n"
           "loop:\nload 0\nint 5\n<\nbz done\n"
           "load 0\nint 1\n+\nstore 0\nb loop\n"
           "done:\nint 1\nreturn\n")
    prog = SSAProgram.from_text(src, strict=False)
    loop = analyze_loops(prog)[0]

    assert loop.prefix_cost >= 105               # the three sha256 at least
    assert loop.available_budget == APP_OPCODE_BUDGET - loop.prefix_cost
    assert loop.budget_bound == loop.available_budget // loop.min_iteration_cost
    # Strictly tighter than ignoring the preamble.
    assert loop.max_iterations < APP_OPCODE_BUDGET // loop.min_iteration_cost

    # NEVER below the dominator sum. Every path to the header crosses all of
    # them, so the cheapest path already costs at least that much — the
    # invariant that makes cheapest-path a strict improvement rather than a
    # different answer. (Measured over 98 mainnet loops: 0 violations, median
    # prefix 33 -> 88.)
    cfg = CFG.of(prog)
    dominator_sum = sum(block_cost(b) for b in cfg.dominators(loop.header)
                        if b is not loop.header)
    assert loop.prefix_cost >= dominator_sum

    # The header's own cost is EXCLUDED — it belongs to the per-iteration cost,
    # and counting it twice would over-subtract and under-report iterations,
    # the unsound direction for an upper bound. Here the whole preamble is one
    # straight line, so the cheapest path to the header IS that preamble.
    preamble = prog.block_containing("contract.teal", 2)
    assert loop.prefix_cost == block_cost(preamble)


def test_no_prefix_when_the_loop_starts_at_entry():
    loop = _loops("#pragma version 10\nloop:\ntxn NumAppArgs\nbnz loop\n"
                  "int 1\nreturn\n")[0]
    assert loop.prefix_cost == 0
    assert loop.available_budget == APP_OPCODE_BUDGET


def test_dot_view_boxes_each_loop_and_marks_the_spent_prefix():
    """The table says what a loop costs; the graph says where it sits and what
    the program already committed on the way in.

    Labels go through `bb_label`, which escapes each PART before joining with
    the DOT break — escaping the joined string doubles the backslash and
    Graphviz prints a literal "\\l" instead of breaking the line."""
    from tealql.tealtools.budget import to_dot

    src = ("#pragma version 10\nbyte 0x00\nsha256\npop\nint 0\nstore 0\n"
           "loop:\nload 0\nint 5\n<\nbz done\n"
           "load 0\nint 1\n+\nstore 0\nb loop\n"
           "done:\nint 1\nreturn\n")
    dot = to_dot(SSAProgram.from_text(src, strict=False))

    assert dot.startswith("digraph loop_bounds {") and dot.rstrip().endswith("}")
    assert "subgraph cluster_0 {" in dot          # the loop is boxed
    assert "iter (budget)" in dot                 # labelled with its bound
    assert "spent before" in dot                  # and with the mandatory prefix
    assert 'label="back"' in dot                  # the back edge is marked
    assert "\\l" in dot and "\\\\l" not in dot    # real DOT breaks, not literals


def test_prefix_is_the_CHEAPEST_PATH_not_just_the_dominators():
    """Where two arms rejoin before the loop, NEITHER dominates the header — so
    a dominator sum ignores both, even though every execution must pay for one.

    The cheapest path counts the cheaper arm, which is the sound choice: any
    real path costs at least that. Here it is 10x the dominator sum.

    Non-negative block costs are what make plain Dijkstra correct — a back edge
    can never shorten a path, so a loop on the way needs no special handling."""
    from tealql.tealtools.cfg import CFG

    src = ("#pragma version 10\n"
           "txn NumAppArgs\nbnz armB\n"
           "byte 0x00\nsha256\npop\nb join\n"            # arm A: sha256 = 35
           "armB:\nbyte 0x00\nkeccak256\npop\n"          # arm B: keccak256 = 130
           "join:\nint 0\nstore 0\n"
           "loop:\nload 0\nint 5\n<\nbz done\n"
           "load 0\nint 1\n+\nstore 0\nb loop\n"
           "done:\nint 1\nreturn\n")
    prog = SSAProgram.from_text(src, strict=False)
    cfg = CFG.of(prog)
    loop = analyze_loops(prog, cfg)[0]

    dominator_sum = sum(block_cost(b) for b in cfg.dominators(loop.header)
                        if b is not loop.header)
    assert loop.prefix_cost > dominator_sum          # strictly better
    # It took the CHEAP arm: enough for sha256, nowhere near keccak256.
    assert loop.prefix_cost >= 35
    assert loop.prefix_cost < 130
