"""Control flow THROUGH a label that has no instructions.

A label with nothing between it and the next label gets a bb id but no `BasicBlock` — a BasicBlock is
built from assignments and it has none. Every CFG edge targeting it was therefore dropped, and each
drop cost two edges: the branch that named the label, and the fallthrough from the block above it.
The block after the label was left with no predecessors at all.

The damage surfaced a long way from the cause. With no successor, the lift terminated the preceding
block by EXITING THE PROGRAM, handing puya whatever value the stack simulation happened to hold —
which puya rejected as `Can only exit with uint64 backed value`, a type error three layers downstream
of a missing edge.

TEALScript emits this shape whenever an `if` ends where a loop continues:

    *if4_end:                <- no instructions
    *for_0_continue:

18 times in Reti's StakingPool and 16 in its ValidatorRegistry. puya-ts never does it, which is why
it went unseen until a TEALScript contract was analysed.
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram


def _cfg(tmp_path, src: str):
    p = tmp_path / "t.teal"
    p.write_text(src)
    prog = SSAProgram(str(p), strict=False)
    g = prog.cfg()
    return {(n.first_line, n.last_line): sorted((s.first_line, s.last_line) for s in g[n]) for n in g}


_ONE_LABEL = """#pragma version 11
\tintc_0
\tbz L_end
\tintc_0
\tpop
L_end:
\tintc_0
\treturn
"""

_EMPTY_LABEL = """#pragma version 11
\tintc_0
\tbz L_end
\tintc_0
\tpop

L_end:

L_cont:
\tintc_0
\treturn
"""


def test_branch_and_fallthrough_survive_an_empty_label(tmp_path):
    """Both edges must reach the block after the empty label, not stop at it."""
    cfg = _cfg(tmp_path, _EMPTY_LABEL)
    assert (9, 11) in cfg, f"block after the empty label missing: {cfg}"
    assert cfg[(2, 3)] == [(4, 5), (9, 11)], f"bz target lost through empty label: {cfg}"
    assert cfg[(4, 5)] == [(9, 11)], f"fallthrough lost through empty label: {cfg}"


def test_an_empty_label_does_not_change_the_shape(tmp_path):
    """The same program with and without the empty label must have the same edge SHAPE.

    Pinned as a comparison rather than as literal line numbers so the property being asserted is
    "an instruction-free label is transparent to control flow", not a particular listing.
    """
    one, empty = _cfg(tmp_path, _ONE_LABEL), _cfg(tmp_path, _EMPTY_LABEL)
    shape = lambda c: sorted(len(v) for v in c.values())
    assert shape(one) == shape(empty), f"empty label changed the CFG shape: {one} vs {empty}"


def test_chained_empty_labels_are_transparent(tmp_path):
    """Several instruction-free labels in a row forward to the first real block.

    Compilers stack them (`*if_end:` `*else_end:` `*for_continue:`), so resolution has to be
    transitive; a single hop would leave the same hole one label further along.
    """
    cfg = _cfg(tmp_path, "#pragma version 11\n\tintc_0\n\tbz L3\n\tintc_0\n\tpop\n\n"
                         "L1:\n\nL2:\n\nL3:\n\nL4:\n\tintc_0\n\treturn\n")
    tail = max(cfg)
    assert cfg[(2, 3)] == sorted({(4, 5), tail}), f"branch not forwarded through the chain: {cfg}"
    assert cfg[(4, 5)] == [tail], f"fallthrough not forwarded through the chain: {cfg}"


def test_no_self_loop_when_an_empty_label_precedes_its_own_block(tmp_path):
    """Forwarding must not invent a self-edge on a loop header.

    `L_top:` labels the loop head; the tail branches back to it. Resolving that back-edge must land
    on the header's block, and must not also add an edge from that block to itself.
    """
    cfg = _cfg(tmp_path, "#pragma version 11\n\nL_top:\n\tintc_0\n\tbnz L_top\n\tintc_0\n\treturn\n")
    for src, dsts in cfg.items():
        assert dsts.count(src) <= 1, f"duplicate self-edge at {src}: {cfg}"
