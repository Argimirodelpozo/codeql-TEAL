"""Soundness properties of :mod:`tealql.tealtools.cost_analysis`.

The module's contract is "no false negatives for budget-exhaustion findings" —
every reported worst-case cumulative must be an OVER-approximation. These pin
the three ways it previously under-approximated.
"""
from __future__ import annotations

from tealql.tealtools.cost_analysis import (
    ASSUMED_GROUP_SIZE,
    _body_summary,
    _merge_states,
    opcode_cost,
    path_ceiling,
    per_line_cost_paths,
)
from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, src: str, name: str = "c.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text(src)
    return SSAProgram(str(p))


_LOOP_CALLING_SUB = """#pragma version 8
int 0
store 0
loop:
load 0
int 4
<
bz done
callsub work
load 0
int 1
+
store 0
b loop
done:
int 1
return
work:
proto 0 0
byte "aaaa"
keccak256
pop
retsub
"""


def _loops_in(region):
    from tealql.tealtools.control_tree import LoopR

    found = []

    def walk(r):
        if isinstance(r, LoopR):
            found.append(r)
        for attr in ("parts", "nodes", "cases", "programs"):
            for child in getattr(r, attr, []) or []:
                walk(child)
        for attr in ("body", "cond", "then_branch", "else_branch", "exit_arm"):
            child = getattr(r, attr, None)
            if child is not None:
                walk(child)

    walk(region)
    return found


def test_loop_containing_callsub_is_still_a_loop(tmp_path):
    """A loop whose body CALLSUBs must survive as a LoopR.

    Loop detection ran on the cut CFG without the synthetic
    ``callsub → continuation`` edges, so the callsub block dead-ended, the
    cycle vanished, and the loop was flattened into a SequenceR — folded as
    a single iteration and reported as exact.
    """
    from tealql.tealtools.control_tree import build_control_tree

    prog = _prog(tmp_path, _LOOP_CALLING_SUB)
    assert _loops_in(build_control_tree(prog)), (
        "loop with a callsub in its body was flattened away")


def test_loop_body_charges_called_subroutine_cost(tmp_path):
    """A loop body that CALLSUBs must be summarised with the callee's cost.

    The BlockR arm charged `callsub` as opcode_cost("callsub") == 1 and
    counted only literal itxn_submits, so a loop calling an expensive
    subroutine looked ~1 unit/iteration — inflating max_iters and
    under-accumulating the per-iteration bases.
    """
    from tealql.tealtools import cost_analysis as ca
    from tealql.tealtools.control_tree import build_control_tree, ProgramR

    prog = _prog(tmp_path, _LOOP_CALLING_SUB)
    tree = build_control_tree(prog)
    # Populate the subroutine summary table exactly as per_line_cost_paths does.
    ca._active_sub_summaries = {}
    try:
        assert isinstance(tree, ProgramR)
        for entry_bb, summary in tree.subroutine_summaries.items():
            ca._active_sub_summaries[id(entry_bb)] = summary
        loops = _loops_in(tree)
        assert loops, "expected the callsub-containing loop"
        body_cost, _ = _body_summary(loops[0].body, ASSUMED_GROUP_SIZE)
    finally:
        ca._active_sub_summaries = {}
    assert body_cost > opcode_cost("keccak256"), (
        f"loop body summarised at {body_cost}; must include the callee's "
        f"keccak256 ({opcode_cost('keccak256')}) — under-approximated")


def test_body_summary_uses_caller_group_size(tmp_path):
    """Nested-loop iteration bounds must use the caller's group_size.

    A larger group size raises path_ceiling, which allows more iterations, so
    the summarised body cost must be monotonically non-decreasing in it. The
    LoopR/ImproperR arms previously hardcoded ASSUMED_GROUP_SIZE.
    """
    from tealql.tealtools.control_tree import build_control_tree

    prog = _prog(tmp_path, """#pragma version 8
int 0
store 0
outer:
load 0
int 3
<
bz done
byte "aa"
keccak256
pop
load 0
int 1
+
store 0
b outer
done:
int 1
return
""")
    tree = build_control_tree(prog)
    small = _body_summary(tree, 1)
    large = _body_summary(tree, 16)
    assert large[0] >= small[0], (
        f"a bigger group budget must not shrink the bound: {large} < {small}")
    assert small != (0, 0)


def test_merge_states_keeps_highest_headroom_state():
    """Past the cap, the state with the most remaining budget must survive.

    Ranking purely by cum could drop a lower-cum/high-inner-txn state whose
    ceiling is far higher, losing the execution that actually produces the
    worst case downstream.
    """
    from tealql.tealtools import cost_analysis as ca

    hi_cum_no_room = (path_ceiling(0) - 1, 0)      # nearly exhausted, no itxns
    lo_cum_big_room = (10, 200)                    # far more ceiling available
    filler = {(i, 0) for i in range(ca.MAX_CUMS_PER_LINE + 50)}

    merged = _merge_states(
        frozenset({hi_cum_no_room, lo_cum_big_room}), frozenset(filler)
    )
    assert len(merged) <= ca.MAX_CUMS_PER_LINE
    assert lo_cum_big_room in merged, (
        "dropped the state with the largest remaining budget")
    assert hi_cum_no_room in merged, "dropped the largest-cum state"


def test_cyclic_improper_region_is_iteration_bounded():
    """A cyclic Improper must be bounded like a loop, not charged one pass."""
    from types import SimpleNamespace

    from tealql.tealtools import cost_analysis as ca
    from tealql.tealtools.control_tree import ImproperR

    class _FakeBlock:
        """A BlockR-shaped stand-in with a fixed cost and no callsubs."""
        def __init__(self, cost):
            self.bb = SimpleNamespace(
                assignments=[SimpleNamespace(op="sha256")] * cost,
                successors=[],
            )

    from tealql.tealtools.control_tree import BlockR
    a = BlockR.__new__(BlockR)
    a.bb = _FakeBlock(1).bb
    b = BlockR.__new__(BlockR)
    b.bb = _FakeBlock(1).bb

    region = ImproperR.__new__(ImproperR)
    region.nodes = [a, b]
    region.edges = [(a, b), (b, a)]        # a genuine cycle
    region.entries = [a]

    one_pass = opcode_cost("sha256") * 2
    cost, _ = _body_summary(region, ASSUMED_GROUP_SIZE)
    assert cost > one_pass, (
        f"cyclic improper summarised at {cost} — only one pass ({one_pass})")
