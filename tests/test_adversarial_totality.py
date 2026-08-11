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
from tealql.tealtools.ssa.relations import (
    frame_unresolved_reads,
    frame_value_sources,
)
from tealql.tealtools.ssa import SSAProgram

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"

_FIXTURES = {
    # A no-proto callee: retsub does not truncate, the callee's stack lands in
    # the continuation verbatim. Must thread (legacy correctness receipt).
    # Function-shaped, so the call PAIRS off the inferred (0, 2) and the
    # continuation keeps its depth — "no pairs" here would be the legacy
    # stranding gap, not a refusal.
    "legacy_verbatim": (
        "#pragma version 8\nint 99\ncallsub legacy\n+\n+\nreturn\n"
        "legacy:\nint 5\nint 6\nretsub\n",
        "clean",
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
    # frame_dig -1 reads the CALLER's stack directly. Read-only — legal, and
    # the negative slot counts as an implicit argument, so the call pairs
    # off the inferred (1, 3).
    "frame_ops_no_proto": (
        "#pragma version 8\nint 9\ncallsub noproto\npop\npop\nint 1\nreturn\n"
        "noproto:\nint 42\nframe_dig -1\nretsub\n",
        "clean",
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
    (:mod:`ssa.frame_slots`) answers it exactly; the proto'd retsub — the same
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
    from tealql.tealtools.ssa.relations import frame_unresolved_reads

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


def test_a_local_bury_recovers_a_return_in_a_multi_entry_poisoned_region(tmp_path):
    """A region-wide bottom anchor is sufficient, not necessary.

    ``first`` is poisoned by its two incoming heights; ``final`` joins it with
    a separate known-height path, giving the connected poisoned region TWO
    entries, so the region plan must refuse. Nevertheless ``frame_bury 0`` in
    ``final`` unconditionally defines return slot 0. With only consuming ops
    after it, every execution reaching retsub returns that exact top value.
    """
    from tealql.tealtools.lift import pre_ir
    from tealql.tealtools.lift.lift import _Lifter
    from tealql.tealtools.ssa.frame_slots import ReturnSlots

    teal = tmp_path / "local-return.teal"
    teal.write_text(
        "#pragma version 8\ncallsub s\npop\nint 1\nreturn\n"
        "s:\nproto 0 1\ntxn NumAppArgs\nbz shallow\n"
        "txn NumLogs\nbz deep\nb direct\n"
        "shallow:\nint 7\nb first\n"
        "deep:\nint 8\nint 9\nb first\n"
        "first:\nb final\n"
        "direct:\nint 10\nb final\n"
        "final:\nframe_bury 0\nretsub\n")
    prog = SSAProgram(str(teal))
    py = prog._pyssa
    retsub = next(op for block in py.blocks for op in block.ops
                  if op.op == "retsub")
    instruction = py._frame_analysis.instructions.get(id(retsub))
    assert isinstance(instruction, ReturnSlots) and 0 in instruction.slots, (
        "the dominating local bury was lost with the unanchored region")

    ir = _Lifter(prog).build()
    assert ir.pass_stats["frame_slot_refusals"] == 0
    returns = [block.terminator for sub in ir.subroutines for block in sub.body
               if isinstance(block.terminator, pre_ir.SubroutineReturn)]
    assert len(returns) == 1
    assert returns[0].result and not isinstance(returns[0].result[0], pre_ir.Undefined)


def test_an_untouched_param_crosses_a_multi_entry_poisoned_region(tmp_path):
    """Distinct top heights do not make an untouched bottom value ambiguous.

    The connected poisoned region has two boundary joins, so it has no single
    phi home. Every boundary snapshot nevertheless carries the same parameter
    at bottom position 0; the equality-only plan must recover it without
    inventing a phi whose arms cannot be tied to the read block's edges.
    """
    from tealql.tealtools.lift.lift import _Lifter

    teal = tmp_path / "multi-entry-param.teal"
    teal.write_text(
        "#pragma version 8\nint 42\ncallsub s\nint 1\nreturn\n"
        "s:\nproto 1 0\ntxn NumAppArgs\nbz shallow\n"
        "txn NumLogs\nbz deep\nb direct\n"
        "shallow:\nint 7\nb first\n"
        "deep:\nint 8\nint 9\nb first\n"
        "first:\nb final\n"
        "direct:\nint 10\nb final\n"
        "final:\nframe_dig -1\npop\nretsub\n")
    prog = SSAProgram(str(teal))
    dig = next(a for a in prog.assignments if a.op == "frame_dig")
    assert dig.inputs and dig.inputs[0].defined_by.location.line == 2

    lifter = _Lifter(prog)
    ir = lifter.build()
    assert ir.pass_stats["frame_slot_refusals"] == 0
    assert ir.pass_stats["frame_position_phis"] == 0
    source = lifter.frame_map.get(dig.outputs[0])
    sub = ir.subroutines[0]
    assert source is sub.parameters[0].register


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

    Faithful lifting needs per-call-site INLINING. SPLICING the body into the
    caller was tried and REVERTED (2026-08-04): it produced correct IR that the
    BACKEND could not lower — app_1050027991 recompiled before and afterwards
    failed with "l-stack too small for store 71" — and that was the only
    contract it reached. Until that is fixed this pins the honest reporting:
    the sub is collected in ``_Lifter.not_function_shaped`` and warned about."""
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
    assert py._height_conflicted
    assert py._height_conflicted <= py._height_poisoned
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


#: A depth-divergent join whose two arms carry the SAME AVM type, so it isolates
#: the merge-width question. Path A reaches `join` holding one cell, path B two;
#: the `pop` takes B's extra cell, and the `+` that consumes the cell path A
#: does not have sits PAST A BRANCH — inside the join block the shallow arm
#: never dips below its own depth, so the dead-arm kill stays out of the way
#: and the merge must carry the missing cell as an explicit unknown.
_DIVERGENT_JOIN = (
    "#pragma version 8\nint 1\ntxn NumAppArgs\nbnz two\nb join\n"
    "two:\nint 8\njoin:\npop\ntxn NumLogs\nbnz other\nint 1\nreturn\n"
    "other:\nint 5\n+\npop\nint 1\nreturn\n"
)


def test_the_lift_merge_keeps_the_deep_paths_cell(tmp_path):
    """The LIFT's join must merge over the MAX predecessor depth, like
    ``ssa.stacksim.walk_routine`` — SSA and lift now share this decision.

    Historically, the lift's private entry-stack merge truncated to the SHALLOWEST
    predecessor, discarding the deeper paths' cells, so a later consume found
    nothing there. Measured as ``AssertionError: l-stack too small for store
    71`` out of Puya's MIR allocator — a crash rather than a wrong value that
    time, but the same root cause every module docstring here warns about: two
    stack models that disagree about the same program point.

    A cell a predecessor lacks contributes ``Undefined`` on that edge. Honest
    and free at runtime: reaching the consume along the shallow path is an AVM
    stack underflow, so that path is already dead."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "divjoin.teal"
    teal.write_text(_DIVERGENT_JOIN)
    rendered = lift(SSAProgram(str(teal))).render()
    assert "undefined" in rendered.lower(), (
        "the shallow path lacks the deep path's cell, so the merge must carry "
        f"an explicit unknown on that edge rather than drop the slot:\n"
        f"{rendered}")
    assert "φ(" in rendered, f"the surviving cell must be a merge:\n{rendered}"
    lift_to_teal(str(teal))          # and it must still reach TEAL


def test_a_typed_phi_with_an_unknown_arm_does_not_kill_the_lift(tmp_path):
    """``_unify_phi_types`` propagates a phi's type to its arguments, but every
    operand class EXCEPT ``Register`` is a frozen dataclass — so writing to one
    raises ``FrozenInstanceError`` and takes the whole lift down.

    ``Undefined`` is exactly such an operand and its ``ir_type`` IS ``"?"``, so
    it is a write target. It reaches a phi argument wherever a merge has an arm
    with no value, which the max-window join above produces from ordinary
    control flow. The crash additionally needs the phi's REGISTER to be typed,
    which a downstream consumer does (`+` forces uint64 here) — that
    combination is why it stayed hidden.

    Skipping non-Registers is also the RIGHT answer, not just a safe one: a
    constant already carries its own type, and an unknown has none to fix."""
    teal = tmp_path / "typedphi.teal"
    teal.write_text(_DIVERGENT_JOIN)
    ir = lift(SSAProgram(str(teal)))          # must not raise
    assert ir is not None


#: The depth-divergent join above with the arms' TYPES crossed: top-aligned over
#: the max window, the deep slot holds bytes on one path and nothing on the
#: other, while the top slot holds bytes on one path and uint64 on the other.
#: Legal, runnable TEAL — the AVM stack is untyped. The `len` that consumes the
#: cell the shallow path lacks sits past a branch, keeping the shallow arm live
#: inside the join block (the dead-arm kill must not swallow the case).
_DIVERGENT_MIXED_JOIN = (
    "#pragma version 8\nbyte \"aa\"\ntxn NumAppArgs\nbnz two\nb join\n"
    "two:\nint 8\njoin:\npop\ntxn NumLogs\nbnz other\nint 1\nreturn\n"
    "other:\nlen\npop\nint 1\nreturn\n"
)


def test_a_divergent_mixed_type_join_reaches_teal(tmp_path):
    """A join whose paths arrive at different DEPTHS and whose merged slots hold
    different AVM TYPES per path must still reach TEAL.

    It lifted but did not lower. The missing-arm cell of the deep slot is an
    ``Undefined``, whose ``ir_type`` stays ``"?"`` (``_unify_phi_types`` rightly
    skips frozen operands: an unknown has no type to fix) — but the translation
    hardcoded ``PT.uint64`` for every ``Undefined``, so once the slot's phi
    settled to BYTES, ``let pc%N: bytes = undefined`` failed Puya's assignment
    check: ``incompatible types on assignment: source = (uint64), target =
    (bytes)``. Uniform-type divergence (above) dodged it only because uint64
    happened to match the hardcode; uniform-depth mixed types dodged it because
    no arm is missing. The fix types the materialised unknown from its phi and
    makes the translation honour the assignment TARGET — an unknown adopting the
    register's recovered type asserts no value, so nothing is coerced.

    The mixed-type TOP slot is legitimately absent from the IR: its only
    consumer is ``pop``, and ``prune_dead_phis`` deliberately refuses to let a
    discard revive a mixed-AVM-type merge."""
    from tealql.tealtools.lift import pre_ir
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "divmixed.teal"
    teal.write_text(_DIVERGENT_MIXED_JOIN)
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert "undefined" in rendered.lower(), (
        f"the shallow path's missing cell must stay an explicit unknown:\n{rendered}")
    # The pre-IR must be SELF-consistent: an Undefined assigned to a typed
    # register carries that register's type (the register is the source of
    # truth; a `?`-typed source under a typed target is the exact shape that
    # lowered as uint64 and crashed).
    for sub in (ir.main, *ir.subroutines):
        for bb in sub.body:
            for node in bb.ops:
                if (isinstance(node, pre_ir.Assignment)
                        and isinstance(node.source, pre_ir.Undefined)
                        and len(node.targets) == 1
                        and node.targets[0].ir_type != "?"):
                    assert node.source.ir_type == node.targets[0].ir_type, (
                        f"untyped undefined under a typed target in:\n{rendered}")
    lift_to_teal(str(teal))          # the crash under test: must reach TEAL


def test_a_mixed_type_merge_into_a_scratch_store_sinks_per_edge(tmp_path):
    """A join slot holding ``byte "aa"`` on one path and ``int 8`` on the other,
    consumed only by ``store 0``, must become one single-typed store per edge —
    ``sink_mixed_phi_scratch_stores``' designed job — with the ORIGINAL values.

    It did not fire: its mixed-AVM detection read types only off REGISTER args,
    and at that stage (before ``materialize_phi_consts``) the merge still
    carries the per-edge CONSTANTS, so the type set came back empty and the phi
    sailed on to materialisation — which then guessed a type PER ARG, giving one
    phi differently-typed arguments, and Puya rejected the lift:
    ``Phi node received arguments with unexpected type(s)``."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "mixstore.teal"
    teal.write_text(
        '#pragma version 8\ntxn NumAppArgs\nbnz two\nbyte "aa"\nb join\n'
        "two:\nint 8\njoin:\nstore 0\nint 1\nreturn\n")
    rendered = lift(SSAProgram(str(teal))).render()
    assert rendered.count("store 0") == 2, (
        f"the store must be sunk into BOTH predecessors:\n{rendered}")
    assert "0x6161" in rendered and "8u" in rendered, (
        f"each edge must store its ORIGINAL value, uncoerced:\n{rendered}")
    assert "φ(" not in rendered, (
        f"no mixed-type merge may survive the sink:\n{rendered}")
    lift_to_teal(str(teal))          # and it must still reach TEAL


def test_an_unsinkable_mixed_type_merge_is_tail_duplicated_exactly(tmp_path):
    """The mixed-type merge feeding a DYNAMIC scratch write (``stores``) is not
    sinkable — the slot index is a runtime value — and no consumer types it, so
    no single typed register can hold it. When the join block is self-contained
    (nothing defined in it escapes, no missing-cell arms, not a loop header),
    ``tail_duplicate_mixed_joins`` deletes the join instead: each predecessor
    gets its own copy consuming ITS path's single-typed value directly.

    That is the fully faithful answer — each path stores its ORIGINAL value,
    which a sibling transaction observes through ``gload``. No merge register
    exists, so no unknown and no coercion: ``itob``-ing the ``int 8`` to make
    types line up would assert a plausible wrong value on a live path."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "mixstores.teal"
    teal.write_text(
        "#pragma version 8\nint 0\ntxn NumAppArgs\nbnz two\nbyte \"aa\"\nb join\n"
        "two:\nint 8\njoin:\nstores\nint 1\nreturn\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert rendered.count("(stores") == 2, (
        f"the join must be duplicated into BOTH predecessors:\n{rendered}")
    assert "0x6161" in rendered and "8u" in rendered, (
        f"each copy must store its ORIGINAL value, uncoerced:\n{rendered}")
    assert "φ(" not in rendered and "undefined" not in rendered.lower(), (
        f"a duplicated join needs no merge and loses no value:\n{rendered}")
    lift_to_teal(str(teal))          # and it must still reach TEAL


def test_a_refused_mixed_merge_keeps_the_explicit_unknown_floor(tmp_path):
    """Tail duplication REFUSES a loop header (self-arm) — restructuring a loop
    is not V1's business — and the merge falls through to the per-use pick: the
    majority-family phi keeps its own family's arm verbatim and the arm the
    register cannot hold becomes an EXPLICIT unknown, never a reinterpreted or
    coerced value. This pins the fall-back ladder: every guard failure lands on
    a total, honest floor rather than a crash."""
    from tealql.tealtools.language.avm import avm
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "mixloop.teal"
    teal.write_text(
        "#pragma version 8\ntxn NumAppArgs\nbnz two\ntxn Sender\nb loop\n"
        "two:\nglobal LatestTimestamp\nloop:\ndup\nint 1\nswap\nstores\n"
        "txn NumLogs\nbnz loop\npop\nint 1\nreturn\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert "φ(" in rendered, (
        f"the refused merge must SURVIVE as a phi, not be duplicated:\n{rendered}")
    assert "undefined" in rendered.lower(), (
        f"the cross-family arm must be an explicit unknown:\n{rendered}")
    for sub in (ir.main, *ir.subroutines):
        for bb in sub.body:
            for ph in bb.phis:
                want = avm(ph.register.ir_type)
                assert want in ("u", "b"), f"an untyped phi survived:\n{rendered}"
                for a in ph.args:
                    got = avm(getattr(a.value, "ir_type", "?"))
                    assert got in ("?", want), (
                        f"phi {ph.register} carries a {got} arm across the AVM "
                        f"divide:\n{rendered}")
    lift_to_teal(str(teal))          # and it must still reach TEAL


def test_a_mixed_register_merge_with_conflicting_typed_uses_splits_per_use(tmp_path):
    """One stack cell holding ``txn Sender`` (bytes) on one path and ``global
    LatestTimestamp`` (uint64) on the other, later consumed by BOTH ``len`` and
    ``+``: no single typed register can carry it, and consumer-driven recovery
    cannot pick a side, so the phi stayed ``?`` with cross-family REGISTER args
    and Puya rejected the lift (``Phi node received arguments with unexpected
    type(s)``).

    ``split_mixed_phis`` is the per-use pick: ONE PHI PER FAMILY, each keeping
    its own family's arms VERBATIM (exactness) with explicit unknowns on the
    others, and each use consuming the family it demands. Sound under
    panic-pruning — reaching ``len`` along the uint64 arm is an AVM type panic,
    so that path is dead at that use, the same argument the depth-divergent
    merge already stands on."""
    from tealql.tealtools.language.avm import avm
    from tealql.tealtools.lift import pre_ir
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "regboth.teal"
    teal.write_text(
        "#pragma version 8\ntxn NumAppArgs\nbnz two\ntxn Sender\nb join\n"
        "two:\nglobal LatestTimestamp\njoin:\ndup\ntxn NumLogs\nbnz blen\n"
        "int 1\n+\npop\npop\nint 1\nreturn\nblen:\nlen\npop\npop\nint 1\nreturn\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    phis = [ph for sub in (ir.main, *ir.subroutines)
            for bb in sub.body for ph in bb.phis]
    assert {avm(ph.register.ir_type) for ph in phis} == {"u", "b"}, (
        f"the mixed cell must split into one phi per demanded family:\n{rendered}")
    for ph in phis:                  # each split phi is family-consistent
        want = avm(ph.register.ir_type)
        for a in ph.args:
            got = avm(getattr(a.value, "ir_type", "?"))
            assert got in ("?", want), (
                f"phi {ph.register} carries a {got} arm:\n{rendered}")
    # Exactness: each family phi keeps its own family's LIVE arm verbatim —
    # the bytes phi carries the Sender register, the uint64 phi the timestamp.
    b_phi = next(ph for ph in phis if avm(ph.register.ir_type) == "b")
    u_phi = next(ph for ph in phis if avm(ph.register.ir_type) == "u")
    assert any(getattr(a.value, "ir_type", "") == "account"
               for a in b_phi.args), (
        f"the bytes phi lost its live Sender arm:\n{rendered}")
    assert any(isinstance(a.value, pre_ir.Register)
               and a.value.ir_type == "uint64" and not a.value.name.startswith("pc%")
               for a in u_phi.args), (
        f"the uint64 phi lost its live timestamp arm:\n{rendered}")
    lift_to_teal(str(teal))          # the crash under test: must reach TEAL


def test_an_any_typed_use_of_a_mixed_register_merge_is_tail_duplicated(tmp_path):
    """The mixed-REGISTER cell (``txn Sender`` vs ``global LatestTimestamp``)
    consumed only by ``stores``: the self-contained join is deleted by tail
    duplication, and each path's copy stores its OWN register directly — the
    Sender on one path, the timestamp on the other, both live values kept
    exactly. Cloning is shallow for the externally-defined registers (pre-IR
    registers are identity-keyed; a deep copy would sever every reference) and
    the merge never exists, so nothing is unknown and nothing is retyped."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "regstores.teal"
    teal.write_text(
        "#pragma version 8\nint 0\ntxn NumAppArgs\nbnz two\ntxn Sender\nb join\n"
        "two:\nglobal LatestTimestamp\njoin:\nstores\nint 1\nreturn\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert rendered.count("(stores") == 2, (
        f"the join must be duplicated into BOTH predecessors:\n{rendered}")
    assert "(txn Sender)" in rendered and "(global LatestTimestamp)" in rendered, (
        f"each copy must consume its path's ORIGINAL register:\n{rendered}")
    assert "φ(" not in rendered and "undefined" not in rendered.lower(), (
        f"a duplicated join needs no merge and loses no value:\n{rendered}")
    lift_to_teal(str(teal))          # and it must still reach TEAL


#: A LEGACY (pre-`proto`) subroutine whose retsub paths leave DIFFERENT depths —
#: not a function, no (nargs, nret) describes it — called from TWO sites that
#: hold different stacks. The only faithful model is one body copy per site.
_TWO_SITE_DIVERGENT = (
    "#pragma version 8\nint 7\ntxn NumAppArgs\nbnz second\ncallsub helper\n"
    "pop\npop\nint 1\nreturn\nsecond:\nint 9\ncallsub helper\npop\npop\npop\n"
    "int 1\nreturn\nhelper:\ntxn NumLogs\nbnz deep\nretsub\ndeep:\nint 5\nretsub\n"
)


def test_a_divergent_legacy_sub_is_spliced_per_call_site(tmp_path):
    """Each call site of a divergent legacy sub gets its OWN copy of the body:
    the `callsub` becomes the jump it really is, the copy's `retsub` a direct
    jump to THAT site's continuation, and the caller's stack flows through
    verbatim — the divergence joins at the continuation as an ordinary
    depth-divergent merge.

    Per-site duplication is what makes `retsub` representable at all with more
    than one caller: the return target is correlated with the entry edge (the
    return-address stack), which a flat CFG cannot express — the 2026-08-04
    in-place splice was reverted over exactly that. A COPY has one continuation,
    so its retsub is a direct jump; and every cloned block, assignment and
    output being a FRESH object (an `@l<site-line>` key suffix — both SSA
    classes hash by value) is what dissolves the documented
    `resim_args`-keyed-by-`id()` identity problem."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "twosite.teal"
    teal.write_text(_TWO_SITE_DIVERGENT)
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert "(helper" not in rendered and "subroutine" not in rendered, (
        f"a spliced sub must not survive as a callable:\n{rendered}")
    assert rendered.count("(txn NumLogs)") == 2, (
        f"each site must own a COPY of the body:\n{rendered}")
    lift_to_teal(str(teal))          # and the copies must lower

    # The old single-site shape (the one the reverted in-place splice broke)
    # rides the same path: one site, one copy, still lowers.
    one = tmp_path / "onesite.teal"
    one.write_text(
        "#pragma version 8\nint 7\ncallsub helper\npop\npop\nint 1\nreturn\n"
        "helper:\ntxn NumLogs\nbnz deep\nretsub\ndeep:\nint 5\nretsub\n")
    r1 = lift(SSAProgram(str(one))).render()
    assert "(helper" not in r1, f"single-site must splice too:\n{r1}"
    lift_to_teal(str(one))


def test_a_divergent_legacy_sub_with_a_nested_call_is_refused_not_broken(tmp_path):
    """The splice guards refuse a divergent legacy sub that CONTAINS a callsub
    (nesting means callsite-map surgery and recursion is outright
    unrepresentable by copies) — the sub keeps the arity-model recovery: it is
    still emitted, still invoked, and the program still reaches TEAL. Refusal
    must degrade, never break."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "nested.teal"
    teal.write_text(
        "#pragma version 8\nint 7\ntxn NumAppArgs\nbnz second\ncallsub helper\n"
        "pop\npop\nint 1\nreturn\nsecond:\nint 9\ncallsub helper\npop\npop\npop\n"
        "int 1\nreturn\nhelper:\ncallsub inner\ntxn NumLogs\nbnz deep\nretsub\n"
        "deep:\nint 5\nretsub\ninner:\nretsub\n")
    ir = lift(SSAProgram(str(teal)))
    rendered = ir.render()
    assert "(helper" in rendered, (
        f"a refused sub must stay a callable (arity-model recovery):\n{rendered}")
    lift_to_teal(str(teal))          # and must still reach TEAL


def test_a_dead_shallow_arm_rejects_like_the_underflow_it_is(tmp_path):
    """A join arm arriving SHALLOWER than the merge window, where the join
    block's own straight line consumes below that arm's depth: every execution
    entering there dies in the ORIGINAL program — an AVM stack underflow, a
    deterministic reject. Lowering the padded unknown to a zero instead made
    the recompiled program APPROVE on that arm — measured live, 5 of 10 dryrun
    inputs diverged (orig=reject, lift=APPROVE) on exactly this program before
    the fix.

    The doomed edge is retargeted to an explicit ``Fail``: both programs
    reject, and since a rejecting transaction discards everything it did
    (group-atomic), rejecting at the join entry is observationally identical
    to underflowing mid-block — which is also why a ``log`` or state write
    before the underflow point does NOT veto the kill."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "deadarm.teal"
    teal.write_text("#pragma version 8\ntxn NumAppArgs\nbnz deep\nb join\n"
                    "deep:\nint 5\njoin:\npop\nint 1\nreturn\n")
    rendered = lift(SSAProgram(str(teal))).render()
    assert "fail" in rendered and "underflow" in rendered, (
        f"the shallow arm must be an explicit reject:\n{rendered}")
    lift_to_teal(str(teal))

    # Atomicity: a log BEFORE the underflow point does not save the arm — the
    # failed transaction discards the log too, so the kill still fires.
    logged = tmp_path / "deadarm_logged.teal"
    logged.write_text("#pragma version 8\ntxn NumAppArgs\nbnz deep\nb join\n"
                      "deep:\nint 5\njoin:\nbyte \"aa\"\nlog\npop\nint 1\nreturn\n")
    r2 = lift(SSAProgram(str(logged))).render()
    assert "fail" in r2 and "underflow" in r2, (
        f"atomicity makes the pre-underflow log unobservable:\n{r2}")
    lift_to_teal(str(logged))


def test_a_live_shallow_arm_keeps_its_unknown_not_a_reject(tmp_path):
    """The dead-arm kill fires ONLY on proven inevitability: a join block that
    never dips below the shallow arm's own depth (the deep cell is consumed
    past a branch) leaves the arm LIVE, and killing it would turn approving
    executions into rejects. The arm keeps the max-window representation — the
    missing cell as an explicit unknown."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "livearm.teal"
    teal.write_text(_DIVERGENT_JOIN)
    rendered = lift(SSAProgram(str(teal))).render()
    assert "fail" not in rendered, (
        f"a live arm must NOT be rejected:\n{rendered}")
    assert "undefined" in rendered.lower(), (
        f"the live shallow arm keeps its explicit unknown:\n{rendered}")
    lift_to_teal(str(teal))


def test_an_unconditional_chain_dip_dooms_the_arm_too(tmp_path):
    """The underflow needn't happen in the join block itself: a shallow arm
    whose doom sits down an UNCONDITIONAL chain (single distinct successor at
    every step) is just as inevitable, so the walk offsets each block's dips
    by the accumulated net effect and kills the edge. Before the walk, this
    shape approved where the original underflow-rejects — same defect as the
    same-block case, one block later."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "chain.teal"
    teal.write_text(
        "#pragma version 8\ntxn NumAppArgs\nbnz deep\nb join\ndeep:\nint 5\n"
        "join:\nint 1\npop\nb tail\ntail:\npop\nint 1\nreturn\n")
    rendered = lift(SSAProgram(str(teal))).render()
    assert "fail" in rendered and "underflow" in rendered, (
        f"the chain-doomed arm must be an explicit reject:\n{rendered}")
    lift_to_teal(str(teal))


def test_a_conditional_dip_past_the_join_keeps_the_arm_alive(tmp_path):
    """A dip that only happens on ONE side of a branch after the join must NOT
    kill the edge: the arm's other side approves in the original (measured
    live: shallow + oc==0 approves in both programs), so an edge-kill would
    reject live executions. The walk stops at the branch; the residual
    divergence on the dipping side is the documented per-arm-provenance gap,
    closable only by duplicating the post-join region per arm."""
    from tealql.tealtools.lift.backend import lift_to_teal

    teal = tmp_path / "crossblock.teal"
    teal.write_text(
        "#pragma version 8\ntxn NumAppArgs\nbnz deep\nb join\ndeep:\nint 5\n"
        "join:\ntxn OnCompletion\nbnz other\nint 1\nreturn\n"
        "other:\npop\nint 1\nreturn\n")
    rendered = lift(SSAProgram(str(teal))).render()
    assert "fail" not in rendered, (
        f"a conditionally-live arm must NOT be rejected:\n{rendered}")
    lift_to_teal(str(teal))


def test_shared_frame_phi_diamonds_are_resolved_once_per_node():
    """A shared phi DAG is linear in its distinct nodes, not its paths.

    Copying the ancestor set for every phi arm revisits the same sub-DAG once
    per path.  The realistic ``phi(previous, previous)`` diamond therefore
    grew exponentially and made hostile frame shapes a cheap analyzer DoS.
    The access counter makes the complexity contract deterministic while the
    root assertion pins the precision that a bare global visited set loses.
    """
    from tealql.tealtools.ssa.stacksim import _frame_cell_root

    accesses = 0

    class SharedPhi:
        def __init__(self, *args):
            self._args = args

        @property
        def args(self):
            nonlocal accesses
            accesses += 1
            return self._args

    root = object()
    value = root
    depth = 16
    for _ in range(depth):
        value = SharedPhi(value, value)

    assert _frame_cell_root(value) is root
    assert accesses <= depth, (
        f"a {depth}-node shared DAG was expanded {accesses} times")


def test_deep_guard_and_loop_value_chains_are_total():
    """Long legal definition chains must not disappear behind RecursionError.

    The security half keeps an attacker-chosen inner app id below an unrelated
    clean predicate: the predicate does not guard the target, so one finding is
    required.  The budget half makes an attacker-derived chain control a loop,
    so one review candidate is required.  Both old recursive walks failed near
    this depth; crash isolation then rendered the security failure as clean.
    """
    from tealql.security import DETECTORS
    from tealql.tealtools.budget import find_budget_exhaustion_candidates

    depth = 600
    passthrough = "int 0\n+\n" * depth
    security = SSAProgram.from_text(
        "#pragma version 10\n"
        "txna ApplicationArgs 1\nbtoi\n"
        "global LatestTimestamp\n"
        + passthrough
        + "assert\n"
        "itxn_begin\nint appl\nitxn_field TypeEnum\n"
        "itxn_field ApplicationID\nitxn_submit\nint 1\nreturn\n"
    )
    findings = DETECTORS["arbitrary-inner-appcall"](security).detect()
    assert len(findings) == 1

    budget = SSAProgram.from_text(
        "#pragma version 10\nloop:\ntxn Fee\n"
        + passthrough
        + "bnz loop\nint 1\nreturn\n"
    )
    candidates = find_budget_exhaustion_candidates(budget)
    assert len(candidates) == 1 and candidates[0].attacker_controlled
