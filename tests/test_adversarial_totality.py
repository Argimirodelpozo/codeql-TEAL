"""The representation must never fail and never lie — on ALL legal TEAL.

The decompiler contract (2026-07-31): arbitrary contracts get pulled off the
chain and lifted. The interim representation may be slow, bloated or imprecise
on hand-written code, but it must always (a) BUILD, (b) assert only true value
facts — an underivable value is an explicit unknown, never a plausible wrong
one — and (c) LIFT to IR without raising.

The sharpest case measured: a callee that consumes the CALLER's stack has no
function signature to lift to, and assuming its caller's values survived
INVERTED a program's outcome against a live AVM. The lift keeps clause (c) by
marking those slots ``Undefined`` — an explicit unknown, the same answer it
already gives a not-function-shaped sub — instead of the stale value. Recovering
the real values there needs per-call-site inlining.

Each fixture here is legal AVM behaviour that no compiler emits — the frame is
a convention, not a boundary, and pre-proto callsub/retsub are just jumps with
NO stack truncation (a no-proto callee's exit stack IS the continuation's
stack, verbatim — which is why the pre-call-model threading is kept, correct if
bloated, for legacy calls).

The third element pins the call-effect class (:meth:`PySSA._classify_call_effects`):
``"clean"`` (residual untouched — deep slots read the callsub block), ``"hard"``
(the callee may have permuted the caller's residual — deep slots refuse), or
``None`` where no verified pair exists.

VERIFIED ON A LIVE AVM (2026-08-01) — the docs call the frame a convention,
which is only half true and misled an earlier draft here:

* ``frame_dig`` / ``frame_bury`` outside the frame are rejected at RUNTIME, not
  just by the assembler, so those shapes cannot execute and are dead;
* PLAIN stack ops are unbounded: ``cover 3`` under a ``proto 1 1`` band runs and
  permutes the caller's values — the real below-band case, and why HARD exists;
* the bound is re-checked at ``retsub``, so a dip must restore the height.
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
    # proto'd callee whose frame_bury targets BELOW its args. The AVM rejects
    # this at runtime, so the program is dead — but it must still build and
    # lift, and must never be read as clean.
    "below_frame_bury_is_dead": (
        "#pragma version 8\nint 99\nint 1\ncallsub evil\npop\npop\nint 1\n"
        "return\nevil:\nproto 1 1\nint 7\nframe_bury -2\nint 5\nretsub\n",
        "hard",
    ),
    # proto'd callee PERMUTING across its band boundary with cover — LEGAL and
    # RUNS on the AVM (the frame bounds frame ops, not plain stack ops), so the
    # caller's residual really is rewritten. Refused by the lift, see below.
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
    return "hard" if py._unsafe_callee_blocks else "clean"


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

    The height set is FINITE — the AVM caps the stack at 1000 (:data:`STACK_MAX`)
    and the opcode budget caps the lap count long before that (this body is 74
    opcodes, so ~9 laps unpooled, a few hundred pooled — and this contract bumps
    its own budget with the inner txn at L471). So per-height cloning is not
    impossible for want of finiteness. What blocks it is:

    * IDENTITY — the SSA layer keys ``SSAVar`` on ``(file, line, index)`` and
      ``BasicBlock`` on ``(file, first_line, last_line)``, so two copies of one
      block collide by construction. Cloning needs a different identity model
      everywhere, not a change here.
    * COST AND STILL-INEXACTNESS — the lap count is a RUNTIME fact (budget
      bumping), so a static clone set has to cover the stack-limit worst case
      (~993 copies of this 7-block body) or k-limit and widen the tail back to
      the refusal this already gives.

    The principled fix is not contexts at all but BOTTOM-anchoring: a band
    position is invariant across laps (frame ops address ``frame_base + N``,
    and the base does not move) — only its TOP-first slot varies, and slots are
    what this model materialises. That is exactly why the structural maps below
    still answer, and what this pins: the band arithmetic refuses, and every
    frame read is still sourced through the call-site and bury-version maps,
    which are anchored structurally rather than by height."""
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
    # The best of the three answers: the read carries its source as an operand,
    # so no bridge is needed. `frame_value_sources` only knows the structural
    # maps and would not list it, and `frame_unresolved_reads` deliberately
    # skips it — counting it as silent would score a RESOLVED read as a blind
    # one, which is the same metric trap in the opposite direction.
    answered = {id(a.outputs[0]) for a in prog.assignments
                if a.op == "frame_dig" and a.inputs and a.outputs}
    silent = [o for b in ambiguous for o in b.ops
              if o.op == "frame_dig"
              and (v := prog.var(o.file, o.line, 1)) is not None
              and id(v) not in sourced and id(v) not in reported
              and id(v) not in answered]
    assert not silent, (
        f"{len(silent)} frame read(s) in the height-ambiguous region are neither "
        f"sourced nor reported — the refusal must degrade to an ANSWERED value "
        f"or a listed unknown, never a silent clean read")


def test_function_shaped_detection_reflects_the_converged_fixpoint(tmp_path):
    """``not_function_shaped`` must report the CONVERGED arities, not an early
    fixpoint iteration.

    ``_infer_arities`` starts every legacy callee at ``(0, 0)`` and iterates.
    On the first pass ``outer``'s call path looks one shallower than its
    sibling — divergent — and only once ``inner`` is known to leave a value do
    the two paths agree. A mark that accumulates across iterations therefore
    reports a sub that IS a function, which would send a reader hunting for an
    inlining problem that does not exist (and, once inlining lands, would
    inline a sub that never needed it)."""
    from tealql.tealtools.lift.lift import _Lifter

    teal = tmp_path / "fixpoint.teal"
    teal.write_text(
        "#pragma version 8\ncallsub outer\nreturn\n"
        "outer:\nint 0\nbnz other\ncallsub inner\nretsub\n"
        "other:\nint 7\nretsub\n"
        "inner:\nint 5\nretsub\n"
    )
    lifter = _Lifter(SSAProgram(str(teal)))
    lifter.build()
    assert not lifter.not_function_shaped, (
        "a sub whose paths agree once its callee's arity is known was reported "
        "as not function-shaped — the mark is accumulating across fixpoint "
        f"iterations: {sorted(s.name for s in lifter.not_function_shaped)}")


def test_a_real_divergent_legacy_sub_is_still_caught():
    """The converged-state fix must not silence the true positive: app_1050193569's
    `label9` returns at depth -1 down one path and -2 down the other with fully
    converged arities, so it genuinely has no single signature."""
    probe = PROBES / "app_1050193569.teal"
    if not probe.exists():
        pytest.skip("app_1050193569 not present")
    from tealql.tealtools.lift.lift import _Lifter

    lifter = _Lifter(SSAProgram(str(probe)))
    lifter.build()
    assert {s.name for s in lifter.not_function_shaped} == {"label9"}


def test_a_callee_that_eats_the_callers_stack_yields_undefined_not_a_stale_value():
    """The measured wrong-answer case, and the answer that replaced it.

    ``perm`` is ``proto 1 1`` and does ``cover 3``, which reaches UNDER its own
    frame band and moves an 8 into the caller's residual. The AVM runs this —
    verified live: the frame bounds ``frame_dig``/``frame_bury`` (runtime error
    outside it) but places NO bound on plain stack ops — so the caller's second
    value really is 8 after the call, and the contract APPROVES.

    ``_resim`` assumed a call leaves everything below its args alone, so the
    lift emitted ``pushints 2 8; ==`` — the STALE pre-call value — and the
    recompiled program REJECTED: 10 of 10 dryrun inputs diverged, outcome
    inverted. No ``(nargs, nret)`` can express "and it ate two of your values",
    so recovering the real value needs per-call-site inlining. What the lift
    owes meanwhile is an explicit unknown, never the stale value."""
    probe = Path(__file__).resolve().parent / "contracts" / "hostile-crossband"
    teal = probe / "crossband.teal"
    if not teal.exists():
        pytest.skip("hostile-crossband fixture not present")
    prog = SSAProgram(str(teal))
    assert prog._pyssa._clobber_callee_keys, (
        "the cross-band cover must be classified as clobbering the caller")
    rendered = lift(prog).render()
    assert "undefined" in rendered, (
        "the clobbered caller slot must lift as an explicit unknown")
    assert "2u" not in rendered, (
        "the lift asserted the STALE pre-call value for a slot the callee "
        f"overwrote — the measured outcome-inverting bug is back:\n{rendered}")


def test_an_unresolved_value_is_tainted_not_clean():
    """An `Undefined` the lift emits must read as TOP to every may-analysis.

    When a callee consumes the caller's own stack, the lift marks those slots
    `Undefined` — it cannot know what the callee left there. That is honest to a
    human reading the IR, but the taint map is keyed by Register, so an
    `Undefined` had NO entry and every consumer read it as *clean*. Measured on
    this contract: attacker-controlled `ApplicationArgs[0]` reaches an inner
    `pay` Amount, and `ir-tainted-fund-flow` reported NOTHING — a silent false
    negative, and the same class as the narrow `frame_dig` fallback that
    produced an output with no inputs.

    Unknown is not clean. It cannot be discharged as "not attacker-controlled",
    so it is now seeded with `UNKNOWN_SOURCE` in both taint fixpoints and
    counted as a source at the sink, which names it in the finding."""
    from tealql.security import DETECTORS

    teal = (Path(__file__).resolve().parent / "contracts" / "hostile-crossband"
            / "crossband_taint.teal")
    if not teal.exists():
        pytest.skip("fixture not present")
    prog = SSAProgram(str(teal))
    prog.propagate_constants()
    vs = DETECTORS["ir-tainted-fund-flow"](prog, file=teal.name).detect()
    assert vs, (
        "an attacker-controlled Amount behind a callee that ate the caller's "
        "stack went UNREPORTED — an unresolved value is being read as clean")


def test_a_panicking_op_survives_into_the_pre_ir_even_when_dead(tmp_path):
    """`+` and `/` are NOT pure in the AVM, and our IR must keep them.

    `int 2^64-1; int 1; +; pop` overflows, and an AVM overflow PANICS — the
    transaction rejects. The result being discarded does not make the op
    unobservable, so the lift must still emit it.

    It does. Recorded here because puya's own optimiser, which
    `lift_to_teal` runs afterwards, then DELETES it: the recompiled program is
    `pushint 1; return`, which APPROVES where the original rejects — measured
    on a live node, 10 of 10 dryrun inputs diverged. Same for a dead
    divide-by-zero; a LIVE overflow is kept, so the trigger is precisely
    dead-code elimination of an op puya considers pure.

    That is a mismatch of assumptions rather than a bug in either side: puya's
    frontend guarantees arithmetic cannot panic, decompiled TEAL guarantees
    nothing. It matters for `lift_to_teal` round-trips, NOT for the decompiled
    view — which is what this pins, so a regression that drops the op from the
    IR itself cannot hide behind the optimiser doing it anyway."""
    teal = tmp_path / "overflow.teal"
    teal.write_text("#pragma version 10\nint 18446744073709551615\nint 1\n+\n"
                    "pop\nint 1\nreturn\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert "(+ " in rendered, (
        "the overflowing add was dropped from the pre-IR — an AVM overflow "
        f"panics, so discarding its result does not make it dead:\n{rendered}")
