"""Pins for the 2026-09-02 audit's SSA/CFG substrate defects. One test per
defect, controls folded in (findings.md 1.2, 1.3, 1.10, 3.1, 3.6)."""
from __future__ import annotations

import pytest

from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, src: str, name: str = "t.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text(src)
    prog = SSAProgram(str(p), strict=False)
    prog.propagate_constants()
    return prog


def _exit_lines(prog, classify) -> set[int]:
    return {bb.last_line for bb in prog.blocks.values() if classify(bb)}


# --- 1.2: off-end exits -----------------------------------------------------

_OC_UPDATE = "txn OnCompletion\nint UpdateApplication\n==\n"


def test_off_end_exits_classified_as_approval_or_rejection(tmp_path):
    """The AVM terminates at ``pc == len(program)`` with the stack top as its
    verdict. Three spellings never reached ``is_approval_exit``: v1 fall-off,
    a branch to a label at EOF, and ``callsub`` as the last instruction (its
    ``retsub`` resumes at EOF). Controls: the same programs with an explicit
    ``return`` (same exit set, shifted to the ``return`` line), an ``int 0``
    off-end twin (rejection, not approval), and ``retsub`` staying no exit."""
    from tealql.tealtools.cfg.cfg import CFG
    from tealql.tealtools.cfg.exits import is_approval_exit, is_rejection_exit
    from tealql.security._program_shape import approving_exits

    # (a) v1 fall-off: the `==` result IS the verdict.
    v1 = _prog(tmp_path, "#pragma version 2\n" + _OC_UPDATE, "v1.teal")
    assert _exit_lines(v1, is_approval_exit) == {4}
    assert _exit_lines(v1, is_rejection_exit) == set()
    assert [bb.last_line for bb in approving_exits(v1)] == [4]

    # (b) branch to a label at EOF — the block has OTHER successors, so only
    # the construction flag can name it.
    bnz = ("#pragma version 10\nint 1\n" + _OC_UPDATE +
           "bnz end\nint 0\nreturn\nend:\n")
    p = _prog(tmp_path, bnz, "bnz.teal")
    assert _exit_lines(p, is_approval_exit) == {6}
    assert _exit_lines(p, is_rejection_exit) == {8}
    assert {bb.last_line for bb in CFG.of(p).exits} == {6, 8}
    ctrl = _prog(tmp_path, bnz + "return\n", "bnz_ctrl.teal")
    assert _exit_lines(ctrl, is_approval_exit) == {10}
    assert _exit_lines(ctrl, is_rejection_exit) == {8}
    # `int 0` off-end twin: provably zero on top → rejection, not approval.
    zero = _prog(tmp_path, bnz.replace("int 1\n", "int 0\n", 1), "bnz0.teal")
    assert _exit_lines(zero, is_approval_exit) == set()
    assert _exit_lines(zero, is_rejection_exit) == {6, 8}

    # (c) callsub as the last instruction: retsub returns to pc == len.
    cs = ("#pragma version 10\nb main\napprove:\nint 1\nretsub\nreject:\nerr\n"
          "main:\n" + _OC_UPDATE + "bz reject\ncallsub approve\n")
    p = _prog(tmp_path, cs, "cs.teal")
    assert p.off_end_exits == {("cs.teal", 13, 13)}
    assert _exit_lines(p, is_approval_exit) == {13}
    assert _exit_lines(p, is_rejection_exit) == {7}
    # `retsub` is NEVER an exit — the successor-less retsub block stays out.
    retsub_bb = next(bb for bb in p.blocks.values()
                     if bb.assignments[-1].op == "retsub")
    assert not retsub_bb.successors
    assert not is_approval_exit(retsub_bb) and not is_rejection_exit(retsub_bb)
    ctrl = _prog(tmp_path, cs + "return\n", "cs_ctrl.teal")
    assert ctrl.off_end_exits == set()
    assert _exit_lines(ctrl, is_approval_exit) == {14}

    # Detector-level: every variant is an unguarded UpdateApplication approval.
    from tealql.security import DETECTORS
    for name, src in (("v1d.teal", "#pragma version 2\n" + _OC_UPDATE),
                      ("bnzd.teal", bnz), ("csd.teal", cs)):
        prog = _prog(tmp_path, src, name)
        assert DETECTORS["unprotected-updatable"](prog).detect(), name
