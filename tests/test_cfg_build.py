"""Seam pins for the CFG extractor floor (``cfg/build.py``).

Each defect here produced a CONFIDENTLY WRONG graph with no diagnostic. The
corpus cannot catch them — all 1166 committed programs are compiler output and
these shapes need hand-written or adversarial source — so they are pinned here.
"""
from __future__ import annotations

from tealql.tealtools.ast.ast import Source
from tealql.tealtools.ast.parse import parse_nodes
from tealql.tealtools.cfg import CFG
from tealql.tealtools.ssa import SSAProgram

V = "#pragma version 8\n"


def _prog(src: str) -> SSAProgram:
    return SSAProgram.from_text(src, strict=False)


def _diags(p: SSAProgram) -> str:
    return " | ".join(d.snippet for d in p.parse_diagnostics)


def test_line_one_is_not_swallowed_by_the_source_node():
    """``Source`` spans the file from line 1, so under the ``(file, line)``
    identity every other node uses it compared EQUAL to whatever sat on line 1
    — and the graph kept only the first arrival. The instruction vanished from
    the SSA silently; for a line-1 ``callsub`` the whole entry block went with
    it and dominance came out inverted (the exit 'dominating' the sub body)."""
    nodes = parse_nodes({"t.teal": b"int 1\nreturn\n"})
    src_node = next(n for n in nodes if isinstance(n, Source))
    line1 = next(n for n in nodes
                 if not isinstance(n, Source) and n.location.start_line == 1)
    assert src_node != line1 and line1 != src_node   # both directions
    assert len({src_node, line1}) == 2

    assert [(a.location.line, a.op) for a in _prog("int 1\nreturn\n").assignments] \
        == [(1, "int"), (2, "return")]

    p = _prog("callsub s\nreturn\ns:\nint 1\nretsub\n")
    c = CFG.of(p)
    assert [b.first_line for b in c.entries] == [1]
    body = next(b for b in c.blocks if b.first_line == 3)
    exit_bb = next(b for b in c.blocks if b.first_line == 2)
    assert not c.dominates(exit_bb, body)


def test_dropped_control_flow_is_diagnosed():
    """Two silent narrowings of the graph. An unresolvable branch target yields
    NO edge, so the branch keeps only its fall-through and the code it reached
    is pruned as unreachable. A target-less ``match``/``switch`` absorbs the
    NEXT instruction as its operand list, deleting it outright."""
    p = _prog(f"{V}int 1\nbnz nowhere\nint 2\nb gone\nint 3\nreturn\n")
    d = _diags(p)
    assert d.count("no label defines") == 2, d       # once each, not once per walk
    assert "nowhere" in d and "gone" in d

    assert _diags(_prog(f"{V}int 1\nswitch a b\nint 2\nreturn\n")
                  ).count("no label defines") == 2   # every arm

    for op in ("match", "switch"):
        assert "absorbed as its operands" in _diags(
            _prog(f"{V}int 1\nint 1\n{op}\nreturn\n")), op

    # A program whose targets all resolve stays clean.
    assert "no label defines" not in _diags(
        _prog(f"{V}int 1\nbnz ok\nint 2\nok:\nint 3\nreturn\n"))


def test_branch_off_the_end_of_the_program_keeps_its_exit():
    """``bz L_end`` where ``L_end:`` is the last line runs off the end, which
    TERMINATES on the AVM. The label starts no BasicBlock, so that edge had
    nowhere to land and vanished — leaving post-dominance to rule the
    fall-through unavoidable. The control case (label followed by real code)
    must still post-dominate, or the fix just declared every branch an exit."""
    p = _prog(f"{V}int 1\nbz L_end\nint 2\nreturn\nL_end:\n")
    c = CFG.of(p)
    head = next(b for b in c.blocks if b.first_line == 2)
    tail = next(b for b in c.blocks if b.first_line == 4)
    assert head._key() in p.off_end_exits and head in c.exits
    assert not c.post_dominates(tail, head)

    p2 = _prog(f"{V}int 1\nbz L\nint 2\nL:\nint 3\nreturn\n")
    c2 = CFG.of(p2)
    assert p2.off_end_exits == set()
    assert c2.post_dominates(next(b for b in c2.blocks if b.first_line >= 5),
                             next(b for b in c2.blocks if b.first_line == 2))
