"""The representation must never fail and never lie — on ALL legal TEAL.

The decompiler contract (2026-07-31): arbitrary contracts get pulled off the
chain and lifted. The interim representation may be slow, bloated or imprecise
on hand-written code, but it must always (a) BUILD, (b) assert only true value
facts — an underivable value is an explicit unknown, never a plausible wrong
one — and (c) LIFT to IR without raising.

Each fixture here is legal AVM behaviour that no compiler emits — the frame is
a convention, not a boundary, and pre-proto callsub/retsub are just jumps with
NO stack truncation (a no-proto callee's exit stack IS the continuation's
stack, verbatim — which is why the pre-call-model threading is kept, correct if
bloated, for legacy calls). ``expect_withdrawn`` pins which shapes the
band-safety scan must flag (deep-slot values refuse there) and which it must
NOT (read-only deep access loses nothing).
"""

import pytest

from tealql.tealtools.lift import lift
from tealql.tealtools.ssa import SSAProgram

_FIXTURES = {
    # A no-proto callee: retsub does not truncate, the callee's stack lands in
    # the continuation verbatim. Must thread (legacy correctness receipt).
    "legacy_verbatim": (
        "#pragma version 8\nint 99\ncallsub legacy\n+\n+\nreturn\n"
        "legacy:\nint 5\nint 6\nretsub\n",
        None,
    ),
    # proto'd callee writing BELOW its args — rewrites the caller's residual.
    "below_frame_bury": (
        "#pragma version 8\nint 99\nint 1\ncallsub evil\npop\npop\nint 1\n"
        "return\nevil:\nproto 1 1\nint 7\nframe_bury -2\nint 5\nretsub\n",
        True,
    ),
    # proto'd callee PERMUTING across its band boundary with cover.
    "cross_band_cover": (
        "#pragma version 8\nint 1\nint 2\nint 3\ncallsub perm\npop\nint 1\n"
        "return\nperm:\nproto 1 1\nint 7\nint 8\ncover 3\nretsub\n",
        True,
    ),
    # proto'd sub passing a nested call more args than its own band holds —
    # the nested retsub truncation eats below the outer band.
    "args_beyond_band": (
        "#pragma version 8\nint 1\nint 2\ncallsub outer\nreturn\n"
        "outer:\nproto 0 1\ncallsub needs2\nretsub\n"
        "needs2:\nproto 2 1\nframe_dig -1\nretsub\n",
        True,
    ),
    # Legacy callee whose net stack effect differs per path — the continuation
    # depth is genuinely path-dependent; unknowns are fine, wrong values not.
    "path_dependent_net": (
        "#pragma version 8\nint 1\ncallsub vary\nreturn\n"
        "vary:\nint 0\nbnz vary_two\nint 5\nretsub\n"
        "vary_two:\nint 6\nint 7\nretsub\n",
        None,
    ),
    # frame ops with NO proto: the frame anchors at the callsub, so
    # frame_dig -1 reads the CALLER's stack directly. Read-only — legal.
    "frame_ops_no_proto": (
        "#pragma version 8\nint 9\ncallsub noproto\npop\npop\nint 1\nreturn\n"
        "noproto:\nint 42\nframe_dig -1\nretsub\n",
        None,
    ),
    # Deep READ-ONLY access below the band must NOT be flagged — a dig copies.
    "deep_dig_read_only": (
        "#pragma version 8\nint 5\ncallsub reader\npop\npop\nint 1\nreturn\n"
        "reader:\nproto 0 1\ndig 0\nretsub\n",
        False,
    ),
    # A join whose paths arrive at DIFFERENT band heights (legal — the AVM has
    # no static verifier). The frame op after it has no single anchor: the
    # depth walk must poison the region, the fat expansion must refuse, and
    # the sub must flag band-unsafe (unknown height reaching retsub) — either
    # path's anchor would read a neighbouring slot on the other path.
    "height_ambiguous_join": (
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 0\nbnz stwo\nint 7\nb sjoin\n"
        "stwo:\nint 7\nint 8\nsjoin:\nframe_dig 0\nretsub\n",
        True,
    ),
    # Control: the same shape with height-CONSISTENT paths must anchor fine
    # and stay unflagged.
    "height_consistent_join": (
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 0\nbnz stwo\nint 7\nb sjoin\n"
        "stwo:\nint 8\nsjoin:\nframe_dig 0\nretsub\n",
        False,
    ),
}


@pytest.mark.parametrize("name", sorted(_FIXTURES))
def test_hostile_teal_builds_and_lifts(name, tmp_path):
    teal, expect_withdrawn = _FIXTURES[name]
    path = tmp_path / f"{name}.teal"
    path.write_text(teal)
    prog = SSAProgram(str(path))            # (a) must BUILD
    assert prog.blocks, f"{name}: build produced no blocks"
    if expect_withdrawn is not None:
        withdrawn = bool(prog._pyssa._value_unsafe_conts)
        assert withdrawn == expect_withdrawn, (
            f"{name}: band-safety scan {'missed a writer' if expect_withdrawn else 'over-flagged a reader'}")
    ir = lift(prog)                          # (c) must LIFT, never raise
    assert ir is not None and getattr(ir, "subroutines", ir), (
        f"{name}: lift returned an empty program")
