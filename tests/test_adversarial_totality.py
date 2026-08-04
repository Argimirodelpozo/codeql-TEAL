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
    # A program whose only subroutine was SPLICED into its caller (a divergent
    # legacy sub with one call site) legitimately has no `subroutines` left,
    # so non-emptiness is asked of the program BODY, not of that list.
    assert ir is not None and (getattr(ir.main, "body", None)
                               or getattr(ir, "subroutines", None)), (
        f"{name}: lift returned an empty program")


def test_a_program_entry_that_is_its_own_loop_header_is_simulated(tmp_path):
    """The AVM starts at PC 0, so the source-first block executes no matter
    what else points at it. A first block that is also a branch target
    (``start:`` ... ``bnz start``, the hand-written retry-loop shape) has
    itself as a predecessor, so ``pyblock_partition``'s no-preds root test
    missed it: NO root existed, the whole program stayed unowned and
    unsimulated, and every op silently kept EMPTY inputs — the
    output-with-no-inputs shape that reads clean to every may-analysis, with
    no refusal marker anywhere. 0 of 1019 mainnet probes have this shape
    (compilers emit a dispatcher first); hand-written TEAL can."""
    teal = tmp_path / "selfloop.teal"
    teal.write_text("#pragma version 8\nstart:\nint 7\ntxn NumAppArgs\n"
                    "bnz start\nint 1\nreturn\n")
    prog = SSAProgram(str(teal))
    py = prog._pyssa
    unowned = [b.key for b in py.blocks if py._bb_to_sub.get(b) is None]
    assert not unowned, f"blocks with no owning routine: {unowned}"
    bnz = next(a for a in prog.assignments if a.op == "bnz")
    assert bnz.inputs, (
        "the loop branch lost its condition operand — the program entry was "
        "never rooted, so nothing was simulated")


def test_a_deep_verbatim_param_chain_leaks_no_private_markers(tmp_path):
    """17+ callsubs each passing their own untouched param on exhausted
    ``_bind_params.resolve``'s hop budget, which then returned the
    still-unresolved ``_Param`` — a PRIVATE simulator marker — into public
    ``Assignment.inputs``, where the first consumer to touch ``.key()`` or
    ``.defined_by`` dies. Exhaustion must be a refusal (the read then shows
    up in ``frame_unresolved_reads``), never a leak."""
    n = 18
    lines = ["#pragma version 8", "int 42", "callsub w1", "pop", "int 1",
             "return"]
    for i in range(1, n + 1):
        lines += [f"w{i}:", "proto 1 1",
                  f"callsub w{i + 1}" if i < n else "frame_dig -1", "retsub"]
    teal = tmp_path / "wrap.teal"
    teal.write_text("\n".join(lines) + "\n")
    prog = SSAProgram(str(teal))
    from tealql.tealtools.ssa.models import Const, SSAVar
    from tealql.tealtools.ssa.models import Phi as PublicPhi
    foreign = [(a.op, a.location.line, type(i).__name__)
               for a in prog.assignments for i in a.inputs
               if not isinstance(i, (SSAVar, PublicPhi, Const))]
    assert not foreign, f"private simulator objects escaped: {foreign}"


def test_a_divergent_legacy_call_recovers_the_callers_residual(tmp_path):
    """A divergent legacy callee's call site must see the PER-PATH truth, not
    the deep path's cells asserted for every path.

    ``vary`` returns one value down one path and two down the other; the
    caller's ``+`` therefore adds (5, its own 55) on the shallow path and
    (7, 6) on the deep one. The uniform window used to push the deep path's
    ``int 6`` as THE second operand — silently wrong on the shallow path,
    where that cell is the caller's own residual. A no-proto ``retsub`` does
    not truncate, so the continuation stack per path is (caller residual) +
    (that path's exit) VERBATIM — every window cell is exactly recoverable as
    a phi over per-path cells, no unknown needed."""
    teal = tmp_path / "divergent_consumer.teal"
    teal.write_text(
        "#pragma version 8\nint 55\ncallsub vary\n+\npop\nint 1\nreturn\n"
        "vary:\ntxn NumAppArgs\nbnz two\nint 5\nretsub\n"
        "two:\nint 6\nint 7\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    assert prog._pyssa._divergent_legacy, (
        "the divergent legacy sub was not marked at the SSA layer")
    from tealql.tealtools.ssa.models import Phi as PublicPhi
    plus = next(a for a in prog.assignments if a.op == "+")
    assert len(plus.inputs) == 2 and all(
        isinstance(i, PublicPhi) for i in plus.inputs), (
        f"expected two per-path phis, got {plus.inputs!r}")

    def leaves(ph):
        return {v.defined_by.ast_code for v in ph.args}

    assert leaves(plus.inputs[0]) == {"int 5", "int 7"}
    assert leaves(plus.inputs[1]) == {"int 55", "int 6"}, (
        "the shallow path's operand must be the CALLER's own residual value, "
        f"not the deep path's cell: {leaves(plus.inputs[1])}")


def test_a_divergent_join_keeps_the_deep_paths_residual(tmp_path):
    """Max-window merge: a join whose paths arrive at different depths must
    keep the DEEP path's below-window cells, as phis marked ``partial``.

    The min-window rule truncated to the shallowest pred, so consuming past
    it read None where the deep path holds a real value. Padding to the
    deepest pred is sound under panic-pruning: consuming a cell on the
    shallow path is an AVM underflow — that path dies at the op, so every
    execution past it took a listed arm. The mark tells reachability-style
    consumers an arm is missing; value consumers may use the args as-is."""
    teal = tmp_path / "maxwin.teal"
    teal.write_text(
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 1\nint 2\nint 3\ntxn NumAppArgs\nbnz stwo\n"
        "b sjoin\nstwo:\nint 8\nsjoin:\n+\npop\npop\npop\nint 1\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    partials = [p for p in prog.phis.values() if p.partial]
    assert len(partials) == 1, (
        f"expected exactly the below-window slot to be partial, got "
        f"{[(p.stack_index, p.partial) for p in prog.phis.values()]}")
    (p,) = partials
    assert p.stack_index == 4 and len(p.args) == 1, (
        "the deep path's bottom cell must survive as the slot-4 phi's only arm")
    full = [p for p in prog.phis.values() if not p.partial]
    assert all(len(p.args) == 2 for p in full), (
        "in-window slots must still merge BOTH paths")


def test_a_net_popping_loops_later_laps_are_marked_not_silent(tmp_path):
    """A loop that net-pops has cells on lap 1 that do not exist on laps >= 2.
    The back-edge fill used to leave such a phi silently forward-only — it
    then read as a definite lap-1 value on EVERY lap. The missing back arm
    must surface as ``partial``."""
    teal = tmp_path / "shrink.teal"
    teal.write_text("#pragma version 8\nint 9\nint 9\nloop:\npop\n"
                    "txn NumAppArgs\nbnz loop\nint 1\nreturn\n")
    prog = SSAProgram(str(teal))
    marked = [(p.stack_index, len(p.args)) for p in prog.phis.values()
              if p.partial]
    assert marked, (
        "the net-popping loop's deeper cell lost its back arm with no mark")


def test_a_frame_read_in_a_varying_height_loop_answers_bottom_anchored(tmp_path):
    """Frame positions are LAP-INVARIANT (the frame base does not move), so a
    pre-loop local read inside a net-growing loop has ONE true value on every
    lap — the region-entry cell — even though the region is depth-poisoned.

    The old behaviour executed ``stack[pos]`` anyway, whose bottom index in a
    bottom-unanchored merged list reads a NEIGHBOURING cell on all laps >= 2:
    a silent wrong-cell arm in the operand phi. The band plan
    (:mod:`ssa.frame_band`) answers it exactly; the proto'd retsub — the same
    bottom-anchored read — recovers too, so the CALLER sees the true value."""
    teal = tmp_path / "bandloop.teal"
    teal.write_text(
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 77\nloop:\nframe_dig 0\npop\nint 5\n"
        "txn NumAppArgs\nbnz loop\nframe_dig 0\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    digs = [a for a in prog.assignments if a.op == "frame_dig"]
    assert digs and all(
        a.inputs and a.inputs[0].defined_by.ast_code == "int 77"
        for a in digs), (
        f"poisoned-region frame reads must resolve to the lap-invariant "
        f"cell: {[(a.location.line, a.inputs) for a in digs]}")
    caller_pop = next(a for a in prog.assignments if a.op == "pop"
                      and a.location.line == 4)
    assert caller_pop.inputs and \
        caller_pop.inputs[0].defined_by.ast_code == "int 77", (
        "the proto'd retsub in the poisoned region is the same bottom-anchored "
        "read — the caller must receive the true return value")


def test_a_bury_dominated_read_in_a_poisoned_region_answers_the_write(tmp_path):
    """A ``frame_bury`` whose position is inside the region's safe prefix and
    which DOMINATES the read answers with its operand, on every lap."""
    teal = tmp_path / "bandbury.teal"
    teal.write_text(
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 77\nloop:\nint 42\nframe_bury 0\nframe_dig 0\n"
        "pop\nint 5\ntxn NumAppArgs\nbnz loop\nint 1\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    dig = next(a for a in prog.assignments if a.op == "frame_dig")
    assert dig.inputs and dig.inputs[0].defined_by.ast_code == "int 42", (
        f"bury-dominated read must take the write's operand, got {dig.inputs}")


def test_a_height_divergent_frame_read_recovers_per_path(tmp_path):
    """At a height-divergent join, ``frame_dig 0`` genuinely reads a
    DIFFERENT cell per path — position 0 is the shallow path's ``int 7`` at
    L10 and the deep path's ``int 7`` at L13. One anchor cannot express that,
    which is why the region is poisoned; but each known predecessor's exit
    list is exact and bottom-anchored, so the per-path cells ARE knowable and
    their merge is a phi. Recovering it beats refusing: a phi over the two
    real values says exactly what the AVM does."""
    from tealql.tealtools.ssa.models import Phi as PublicPhi

    teal = tmp_path / "bandamb.teal"
    teal.write_text(
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 0\nbnz stwo\nint 7\nb sjoin\n"
        "stwo:\nint 7\nint 8\nsjoin:\nframe_dig 0\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    dig = next(a for a in prog.assignments if a.op == "frame_dig")
    assert dig.inputs and isinstance(dig.inputs[0], PublicPhi), (
        f"the per-path cells must merge into a phi, got {dig.inputs}")
    lines = {v.line for v in dig.inputs[0].args}
    assert lines == {10, 13}, (
        f"the phi must carry BOTH paths' bottom cells, got lines {lines}")


def test_an_unplaceable_frame_read_refuses_and_is_listed(tmp_path):
    """Where the band plan cannot place a read — here position 1, which the
    shallow path does not even have (its whole frame is one cell) — the read
    must REFUSE and be LISTED, never answered with the deep path's cell."""
    from tealql.tealtools.passes.frame_flow import frame_unresolved_reads

    teal = tmp_path / "bandunplaceable.teal"
    teal.write_text(
        "#pragma version 8\nint 1\ncallsub s\npop\nreturn\n"
        "s:\nproto 0 1\nint 0\nbnz stwo\nint 7\nb sjoin\n"
        "stwo:\nint 7\nint 8\nsjoin:\nframe_dig 1\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    dig = next(a for a in prog.assignments if a.op == "frame_dig")
    assert not dig.inputs, (
        f"a read below no path's floor must refuse, got {dig.inputs}")
    assert any(a.location.line == dig.location.line
               for a in frame_unresolved_reads(prog)), (
        "the refused read must be LISTED, not silent")


def test_a_cross_band_callees_effect_is_recovered_not_blanked(tmp_path):
    """The measured outcome-inverting shape, recovered with REAL values.

    ``perm`` is ``proto 1 1`` and ``cover 3``s its 8 UNDER the band into the
    caller's residual — legal, runs (verified live). The old answer withdrew
    the caller's residual (honest Nones). Every AVM stack op's effect is
    static, so :mod:`ssa.callee_effects` computes the rewrite exactly for
    tree-shaped callsub-free callees: the caller's post-call comparison must
    see the CALLEE's 8 as its operand — the value the AVM really leaves
    there — with no unknown anywhere."""
    teal = tmp_path / "crossband.teal"
    teal.write_text(
        "#pragma version 8\nint 1\nint 2\nint 3\ncallsub perm\npop\nint 8\n"
        "==\nreturn\n"
        "perm:\nproto 1 1\nint 7\nint 8\ncover 3\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    assert prog._pyssa._effect_summaries, (
        "the cross-band callee must yield an effect summary")
    eq = next(a for a in prog.assignments if a.op == "==")
    srcs = {(i.defined_by.ast_code, i.defined_by.location.line)
            for i in eq.inputs}
    assert ("int 8", 13) in srcs, (
        f"the comparison must see the CALLEE's moved 8 (line 13), got {srcs}")
    assert not any(i is None for i in eq.inputs), (
        "the recovered operand must be a real value, not a refusal")
    # The classification is UNCHANGED — the callee still counts unsafe/hard
    # (the lift keeps Undefining until inlining lands there); only the SSA
    # residual is recovered.
    assert prog._pyssa._unsafe_callee_blocks


def test_a_single_site_divergent_legacy_sub_is_spliced_into_its_caller(tmp_path):
    """A pre-``proto`` ``callsub``/``retsub`` is a JUMP that truncates
    nothing, so a divergent legacy sub with ONE call site is faithfully
    lifted by splicing its body into the caller — no signature to
    over-declare, so no ``Undefined``.

    ``vary`` leaves 1 value down one path and 2 down the other, on top of the
    caller's own ``int 55``. Spliced, the caller's ``+`` sees the paths merge
    at the continuation, which is an ordinary depth-divergent join: the
    max-window merge pairs the shallow path's cells ``(5, 55)`` with the deep
    path's ``(7, 6)``, so the addition is ``5 + 55 = 60`` down one path and
    ``7 + 6 = 13`` down the other — exactly the AVM's two outcomes, with the
    caller's own value recovered rather than padded away."""
    from tealql.tealtools.lift.lift import _Lifter

    teal = tmp_path / "vary_spliced.teal"
    teal.write_text(
        "#pragma version 8\nint 55\ncallsub vary\n+\npop\nint 1\nreturn\n"
        "vary:\ntxn NumAppArgs\nbnz two\nint 5\nretsub\n"
        "two:\nint 6\nint 7\nretsub\n"
    )
    lifter = _Lifter(SSAProgram(str(teal)))
    ir = lifter.build()
    assert lifter._flat_entries, (
        "a divergent legacy sub with ONE call site must be spliced")
    rendered = ir.render()
    assert "undefined" not in rendered.lower(), (
        f"splicing must leave no explicit unknown:\n{rendered}")
    # Both operand pairs must be present: the phis merge (5, 7) and (55, 6).
    assert "55u" in rendered and "5u" in rendered and "6u" in rendered \
        and "7u" in rendered, (
        f"every path's real value must survive the splice:\n{rendered}")


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

    DETECTION is what this pins, and it stays load-bearing after splicing:
    the decision to splice is taken FROM this set, and a sub with several call
    sites cannot be spliced (one body would need one identity per site, which
    the lift does not have) so it still lifts with the padding above. The
    single-site splice is pinned separately, by
    ``test_a_single_site_divergent_legacy_sub_is_spliced_into_its_caller``."""
    from tealql.tealtools.lift.lift import _Lifter

    teal = tmp_path / "vary.teal"
    teal.write_text(_FIXTURES["path_dependent_net"][0])
    prog = SSAProgram(str(teal))
    lifter = _Lifter(prog)
    ir = lifter.build()
    assert ir is not None
    assert lifter.not_function_shaped, (
        "a legacy callee with divergent retsub depths must be reported — the "
        "splice decision is taken from this set")


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


def test_a_callee_that_eats_the_callers_stack_yields_the_real_moved_value():
    """The measured wrong-answer case, and the answer that now replaces it.

    ``perm`` is ``proto 1 1`` and does ``cover 3``, which reaches UNDER its own
    frame band and moves an 8 into the caller's residual. The AVM runs this —
    verified live: the frame bounds ``frame_dig``/``frame_bury`` (runtime error
    outside it) but places NO bound on plain stack ops.

    ``_resim`` assumed a call leaves everything below its args alone, so the
    lift emitted ``pushints 2 8; ==`` — the STALE pre-call value — and the
    recompiled program REJECTED: 10 of 10 dryrun inputs diverged, outcome
    inverted. The interim answer was ``Undefined``: honest, but a refusal.

    Every AVM stack op's effect is STATIC, so :mod:`ssa.callee_effects` now
    computes what the callee really leaves there, and the lift carries it
    across (a moved caller cell and a passed argument are values the caller
    already holds; a callee-produced constant re-materialises). MEASURED ON A
    LIVE AVM (2026-08-04), stack trace through the comparison::

        [1, 8] -> int 8 -> [1, 8, 8] -> == -> [1, 1] -> PASS

    so the comparison really is ``8 == 8``, which is exactly what the lift
    emits. The stale ``2u`` must never come back, and neither should the
    refusal."""
    probe = Path(__file__).resolve().parent / "contracts" / "hostile-crossband"
    teal = probe / "crossband.teal"
    if not teal.exists():
        pytest.skip("hostile-crossband fixture not present")
    prog = SSAProgram(str(teal))
    assert prog._pyssa._clobber_callee_keys, (
        "the cross-band cover must be classified as clobbering the caller")
    rendered = lift(prog).render()
    assert "== 8u 8u" in rendered, (
        "the clobbered slot must carry the callee's MOVED value — the live "
        f"AVM compares 8 with 8 here:\n{rendered}")
    assert "2u" not in rendered, (
        "the lift asserted the STALE pre-call value for a slot the callee "
        f"overwrote — the measured outcome-inverting bug is back:\n{rendered}")
    assert "undefined" not in rendered.lower(), (
        f"a recoverable clobbered slot must not lift as unknown:\n{rendered}")


def test_an_unresolved_value_is_tainted_not_clean():
    """An `Undefined` the lift emits must read as TOP to every may-analysis.

    When a callee consumes the caller's own stack and the effect summary
    cannot carry the value across — a callee-produced RUNTIME value has no
    `(nargs, nret)` to travel on — the lift marks that slot `Undefined`. That
    is honest to a human reading the IR, but the taint map is keyed by
    Register, so an `Undefined` had NO entry and every consumer read it as
    *clean*: a silent false negative, the same class as the narrow
    `frame_dig` fallback that produced an output with no inputs.

    Unknown is not clean. It cannot be discharged as "not attacker-
    controlled", so it is seeded with `UNKNOWN_SOURCE` in both taint
    fixpoints and counted as a source at the sink, which names it in the
    finding."""
    from tealql.security import DETECTORS

    teal = (Path(__file__).resolve().parent / "contracts" / "hostile-crossband"
            / "crossband_taint_runtime.teal")
    if not teal.exists():
        pytest.skip("fixture not present")
    prog = SSAProgram(str(teal))
    prog.propagate_constants()
    vs = DETECTORS["ir-tainted-fund-flow"](prog, file=teal.name).detect()
    assert vs, (
        "an unresolvable Amount behind a callee that ate the caller's stack "
        "went UNREPORTED — an unresolved value is being read as clean")


def test_a_recovered_crossband_amount_is_not_reported_as_attacker_controlled():
    """The counterpart: where the moved value IS recoverable, the honest
    answer is NO finding — and the old `Undefined` was a FALSE POSITIVE.

    ``crossband_taint.teal`` was long read as "attacker-controlled
    ApplicationArgs[0] reaches an inner pay Amount". MEASURED ON A LIVE AVM
    (2026-08-04) it does not: ``cover 3`` buries the attacker's value BELOW
    the frame base, the caller's `pop` then discards it, and the constant 8
    the callee pushed is what reaches ``itxn_field Amount``. Dryrun receipts,
    same shape with the surviving cell returned::

        no cover:  arg0=0 -> REJECT, arg0=7 -> PASS   (cell IS the attacker's)
        cover 3:   arg0=0 -> PASS,   arg0=7 -> PASS   (cell is the constant 8)

    The finding only ever existed because the slot was `Undefined` and
    `UNKNOWN_SOURCE` counted it as a source. Recovering the real value
    retires it. A regression here means the recovery broke and the unknown —
    with its false positive — is back."""
    from tealql.security import DETECTORS

    teal = (Path(__file__).resolve().parent / "contracts" / "hostile-crossband"
            / "crossband_taint.teal")
    if not teal.exists():
        pytest.skip("fixture not present")
    prog = SSAProgram(str(teal))
    prog.propagate_constants()
    vs = DETECTORS["ir-tainted-fund-flow"](prog, file=teal.name).detect()
    assert not vs, (
        "the Amount here is the callee's CONSTANT 8 on a live AVM, not the "
        f"attacker's value — reporting it is a false positive: {vs}")


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
