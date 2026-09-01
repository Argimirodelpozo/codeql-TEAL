"""Pins for the 2026-09-01 audit's security-layer defects that fit no existing
fixture family. One test per defect, controls folded in."""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, src: str) -> SSAProgram:
    p = tmp_path / "t.teal"
    p.write_text(src)
    return SSAProgram(str(p), strict=False)


def _zero_return_bb(prog):
    from tealql.tealtools.ssa import const_int
    for bb in prog.blocks.values():
        a = bb.assignments
        if (len(a) >= 2 and a[-1].op == "retsub"
                and a[-2].outputs and const_int(a[-2].outputs[0]) == 0):
            return bb
    raise AssertionError("no `int 0; retsub` block found")


def test_callee_zero_return_credit_respects_branch_polarity(tmp_path):
    """`callsub check; bnz reject` rejects on NONZERO — the callee's 0-return
    APPROVES, so crediting it as a rejection turned a non-guard into a guard.
    Controls: `assert` (fails on 0 → rejects), `bz reject` (0 takes the reject
    branch → rejects), and `!; assert` (passes on 0 → NOT a rejection)."""
    from tealql.security._enforcement import _callee_zero_return_rejects

    shapes = {
        # (caller acts on result as ...): credited as rejection?
        "callsub check\nassert\nint 1\nreturn": True,
        "callsub check\nbz reject\nint 1\nreturn": True,
        "callsub check\nbnz reject\nint 1\nreturn": False,
        "callsub check\n!\nassert\nint 1\nreturn": False,
    }
    for body, expected in shapes.items():
        prog = _prog(tmp_path, "#pragma version 8\n" + body +
                     "\nreject:\nint 0\nreturn\n"
                     "check:\nproto 0 1\nint 0\nretsub\n")
        got = _callee_zero_return_rejects(prog, _zero_return_bb(prog))
        assert got is expected, f"{body!r}: credited={got}, want {expected}"
