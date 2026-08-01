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
bloated, for legacy calls).

The third element pins the call-effect class (:meth:`PySSA._classify_call_effects`):
``"clean"`` (residual untouched — deep slots read the callsub block),
``"writer"`` (below-band writes at static positions — deep slots read the
retsub through the truncation mapping and SEE the writes), ``"hard"``
(unmodelable — deep slots refuse), or ``None`` where no verified pair exists.
"""

from pathlib import Path

import pytest

from tealql.tealtools.lift import lift
from tealql.tealtools.passes.frame_flow import (
    frame_unresolved_reads,
    frame_value_sources,
)
from tealql.tealtools.ssa import SSAProgram

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"

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
        "writer",
    ),
    # proto'd callee PERMUTING across its band boundary with cover.
    "cross_band_cover": (
        "#pragma version 8\nint 1\nint 2\nint 3\ncallsub perm\npop\nint 1\n"
        "return\nperm:\nproto 1 1\nint 7\nint 8\ncover 3\nretsub\n",
        "hard",
    ),
    # proto'd sub passing a nested call more args than its own band holds —
    # the nested retsub truncation eats below the outer band.
    "args_beyond_band": (
        "#pragma version 8\nint 1\nint 2\ncallsub outer\nreturn\n"
        "outer:\nproto 0 1\ncallsub needs2\nretsub\n"
        "needs2:\nproto 2 1\nframe_dig -1\nretsub\n",
        "hard",
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
        "clean",
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
        "hard",
    ),
    # Control: the same shape with height-CONSISTENT paths must anchor fine
    # and stay unflagged.
    "height_consistent_join": (
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 0\nbnz stwo\nint 7\nb sjoin\n"
        "stwo:\nint 8\nsjoin:\nframe_dig 0\nretsub\n",
        "clean",
    ),
}


def _effect_class(py) -> "str | None":
    if not py._call_pairs:
        return None
    if py._value_unsafe_conts:
        return "hard"
    if py._writer_conts:
        return "writer"
    return "clean"


@pytest.mark.parametrize("name", sorted(_FIXTURES))
def test_hostile_teal_builds_and_lifts(name, tmp_path):
    teal, expect_class = _FIXTURES[name]
    path = tmp_path / f"{name}.teal"
    path.write_text(teal)
    prog = SSAProgram(str(path))            # (a) must BUILD
    assert prog.blocks, f"{name}: build produced no blocks"
    assert _effect_class(prog._pyssa) == expect_class, (
        f"{name}: call-effect classification moved — a callee that writes or "
        f"permutes the caller's residual must never be read as clean")
    ir = lift(prog)                          # (c) must LIFT, never raise
    assert ir is not None and getattr(ir, "subroutines", ir), (
        f"{name}: lift returned an empty program")


def test_a_path_divergent_legacy_callee_is_reported_not_function_shaped(tmp_path):
    """A legacy sub whose ``retsub`` sites leave different depths IS NOT A
    FUNCTION, and the lift must say so rather than let the gap read as ordinary.

    ``vary`` returns one value down one path and two down the other. A
    pre-``proto`` ``retsub`` does not truncate — it is a jump — so this is legal
    TEAL, and NO single ``(nargs, nret)`` describes it: declare 2 and the shallow
    path over-returns (its second "return" is the CALLER's own pre-call value);
    declare 1 and the deep path's extra value is dropped. The inferred signature
    takes the max, so the shallow path is padded with ``Undefined`` — an explicit
    unknown rather than a wrong value, which keeps the never-lie contract, but
    the caller's value below the call is lost.

    Faithful lifting needs per-call-site INLINING (the IR can express it — its
    block ids are synthetic, unlike the SSA layer's source-position identities).
    Until that lands, this pins the honest reporting: the sub is collected in
    ``_Lifter.not_function_shaped`` and warned about."""
    from tealql.tealtools.lift.lift import _Lifter

    teal = tmp_path / "vary.teal"
    teal.write_text(_FIXTURES["path_dependent_net"][0])
    prog = SSAProgram(str(teal))
    lifter = _Lifter(prog)
    ir = lifter.build()
    assert ir is not None
    assert lifter.not_function_shaped, (
        "a legacy callee with divergent retsub depths must be reported — its "
        "lifted signature over-declares the shallow path")


def test_height_ambiguous_region_still_answers_every_frame_read():
    """Where the band anchor is refused, the VALUES must still be answered.

    app_3300088574 has a loop that leaks one value per lap (`box_del`'s bool is
    never consumed), so the header's stack height differs on every iteration.
    That is legal and works at runtime precisely because ``frame_dig`` anchors
    at the frame BASE, which does not move — but our slot model materialises one
    entry stack per block, so a top-first slot means a DIFFERENT band position on
    each lap. Hence the refusal (:meth:`_compute_entry_depths` poisoning).

    Per-height cloning cannot rescue this one: the height set is unbounded
    (one more cell per lap), so there is no finite set of contexts to clone —
    and for the finite (branch-join) case the SSA layer's identity model,
    ``(file, line, index)``, forbids two copies of a block anyway. The right
    degradation is what this pins: the band arithmetic refuses, and every frame
    read is still sourced through the call-site and bury-version maps, which are
    anchored structurally rather than by height."""
    probe = PROBES / "app_3300088574.teal"
    if not probe.exists():
        pytest.skip("app_3300088574 not present")
    prog = SSAProgram(str(probe))
    py = prog._pyssa
    ambiguous = [b for b in py.blocks
                 if py._bb_to_sub.get(b) is not None
                 and py._frame_edepth.get(b.key) is None]
    assert ambiguous, "fixture no longer exercises a height-ambiguous region"
    sourced = {id(v) for v in frame_value_sources(prog)}
    reported = {id(a.outputs[0]) for a in frame_unresolved_reads(prog) if a.outputs}
    silent = [o for b in ambiguous for o in b.ops
              if o.op == "frame_dig"
              and (v := prog.var(o.file, o.line, 1)) is not None
              and id(v) not in sourced and id(v) not in reported]
    assert not silent, (
        f"{len(silent)} frame read(s) in the height-ambiguous region are neither "
        f"sourced nor reported — the refusal must degrade to an ANSWERED value "
        f"or a listed unknown, never a silent clean read")
