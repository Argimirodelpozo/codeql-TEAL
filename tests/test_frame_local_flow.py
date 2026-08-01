"""A value parked in a frame slot must not lose its taint on the way back out.

PySSA models a frame op as a wide band read, and the soundness argument for the
may-analyses rests on that: a read that depends on the whole band
over-approximates, which is safe. But the argument only holds while the band is
there. When the fat expansion cannot locate it, the op falls back to the narrow
arity, where ``frame_dig`` is ``(0, 1)`` — an output with NO inputs. That is not a
wider read, it is an EMPTY one, and a value with no incoming edge reads as clean
to every may-analysis, so ``frame_bury`` a tainted value and ``frame_dig`` it back
and the taint is simply gone. False negative, not imprecision.

``frame_param_sources`` had always reconstructed one half of this (the caller
argument behind a param read). The local half — the value a ``frame_bury`` wrote
— was computed by ``frame_resolution`` and consumed ONLY by the lift, so on the
SSA layer 394 of 564 local frame reads across 40 mainnet probes had no incoming
edge at all. ``frame_local_sources`` joins the two halves
(``dig_local`` x ``bury`` on ``(slot, version)``) and
``frame_value_sources`` unions them for the MAY consumers.
"""
import glob
import random
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.passes.frame_flow import (
    frame_local_sources,
    frame_param_sources,
    frame_unresolved_reads,
    frame_value_sources,
)

TESTS = Path(__file__).resolve().parent
PROBES = TESTS / "mainnet-random-probes"


def _sample(n=12):
    files = sorted(glob.glob(str(PROBES / "*.teal")))
    if len(files) < n:
        pytest.skip("probe corpus not present")
    random.Random(7).shuffle(files)
    return files[:n]


def _frame_digs(prog):
    """``(immediate, assignment)`` for every ``frame_dig``, immediate parsed."""
    out = []
    for a in prog.assignments:
        if a.op != "frame_dig":
            continue
        try:
            out.append((int(str(a.immediates).strip().split()[0]), a))
        except (ValueError, IndexError):
            continue
    return out


@pytest.mark.parametrize("teal", _sample(), ids=lambda p: Path(p).name)
def test_every_local_frame_read_is_sourced_or_reported(teal):
    """THE property, and it is TOTAL: a ``frame_dig`` of a local that carries no
    band is either given a source, or listed by ``frame_unresolved_reads``. There
    is no silent third category — that third category was the bug, 394 of 564
    such reads over a 40-probe sample reading as clean with nothing to say so.

    Do NOT scope this by slot version, which an earlier draft of this test did.
    ``fresh()`` numbers the FIRST write to a slot version 0, so "version > 0" is
    not "was written" — it silently excused real bury pairings, including the
    ``callsub``-return case that has a demonstrated taint path behind it."""
    prog = SSAProgram(teal)
    sourced = {id(k) for k in frame_value_sources(prog)}
    reported = {id(a.outputs[0]) for a in frame_unresolved_reads(prog) if a.outputs}
    silent = []
    for n, a in _frame_digs(prog):
        if n < 0 or a.inputs or not a.outputs:
            continue
        oid = id(a.outputs[0])
        if oid not in sourced and oid not in reported:
            silent.append(a)
    assert not silent, (
        f"{len(silent)} frame read(s) of a local are neither sourced nor reported, "
        f"so they read as clean with nothing recording the gap: "
        f"{[f'{a.location.file}:{a.location.line}' for a in silent[:5]]}")


@pytest.mark.parametrize("teal", _sample(6), ids=lambda p: Path(p).name)
def test_local_sources_are_disjoint_from_params_and_well_formed(teal):
    """The two halves answer about different reads, and every source is a real
    value — a bogus source would invent taint rather than lose it."""
    prog = SSAProgram(teal)
    params, locals_ = frame_param_sources(prog), frame_local_sources(prog)
    assert not (set(map(id, params)) & set(map(id, locals_))), \
        "a frame read is either a param read or a local read, never both"
    union = frame_value_sources(prog)
    assert len(union) == len(params) + len(locals_)
    for dig_out, srcs in locals_.items():
        assert srcs, "an empty source set must be omitted, not recorded"
        for s in srcs:
            assert s is not None


def test_may_consumers_use_the_unioned_map():
    """The join is useless if a consumer still asks for params only, and three of
    them (engine, taint_graph, byte_taint) are wired by import name where a revert
    would be invisible. ``byte_taint`` is the one that exposes its map on the
    result, so assert the local half is actually in there."""
    from tealql.tealtools.dataflow.byte_taint import byte_taint

    probe = PROBES / "app_3300088574.teal"
    if not probe.exists():
        pytest.skip("app_3300088574 not present")
    prog = SSAProgram(str(probe))
    locals_ = frame_local_sources(prog)
    assert locals_, "fixture no longer has local frame reads — pick another probe"
    res = byte_taint(prog)
    got = {id(k) for k in res.frame_src}
    assert got & {id(k) for k in locals_}, (
        "byte_taint's frame bridge carries no local frame reads — it is back on "
        "frame_param_sources, so a value read out of a frame slot reads as clean")


def test_taint_survives_a_frame_local_roundtrip():
    """End to end on a real contract: the SSA user-input taint must reach STRICTLY
    more values once the local half is supplied. app_3300088574 gains 281 tainted
    values, app_3300249437 gains 12 — values that were reachable from attacker
    input all along and read as clean."""
    from tealql.security import _itxn_taint as IT
    from tealql.security._value_flow import (_frame_param_sources_cached,
                                             _frame_value_sources_cached)

    probe = PROBES / "app_3300088574.teal"
    if not probe.exists():
        pytest.skip("app_3300088574 not present")
    saved = IT._frame_value_sources_cached
    try:
        p_old = SSAProgram(str(probe)); p_old.propagate_constants()
        IT._frame_value_sources_cached = _frame_param_sources_cached   # params only
        old = IT._compute_user_input_taint(p_old)
        p_new = SSAProgram(str(probe)); p_new.propagate_constants()
        IT._frame_value_sources_cached = _frame_value_sources_cached
        new = IT._compute_user_input_taint(p_new)
    finally:
        IT._frame_value_sources_cached = saved
    n_old = sum(1 for v in old.values() if v)
    n_new = sum(1 for v in new.values() if v)
    assert n_new > n_old, (
        f"the frame-local edge carried no taint ({n_old} -> {n_new}) — either the "
        "join broke or the MAY consumers stopped using frame_value_sources")


def test_the_callsub_return_blind_spot_is_closed():
    """app_2450560800's two famous unsourceable reads are SOURCED now — to the
    callee's actual return value.

    Both are the ``callsub``-return shape (`callsub label74; frame_bury 0; ...
    frame_dig 0; itob; concat; log`): the buried value is what the call left on
    top, which the old stack model could not attribute (no routine-relative
    depth past a ``callsub``), so the reads sat in ``frame_unresolved_reads``
    and anything reaching them was invisible to the taint layer — a
    demonstrated false-negative path. The call-aware model (2026-07-31) gives
    the continuation its depth and threads the callee's return into the bury,
    so the digs now source from inside the callees: L1390 from label74's
    returned ``intc_0`` (L872), L1440 from its callee's ``extract`` (L1201).
    Pinned positively — if either read goes dark again, the stack model has
    stopped understanding calls."""
    probe = PROBES / "app_2450560800.teal"
    if not probe.exists():
        pytest.skip("app_2450560800 not present")
    prog = SSAProgram(str(probe))
    assert not frame_unresolved_reads(prog), "the closed blind spot re-opened"

    def _leaf_lines(srcs) -> set:
        out: set = set()
        for s in srcs:
            for leaf in (s.args if getattr(s, "args", None) else (s,)):
                line = getattr(leaf, "line", None)
                if line is not None:
                    out.add(line)
        return out

    by_line = {}
    for dig_out, srcs in frame_local_sources(prog).items():
        by_line[dig_out.defined_by.location.line] = srcs
    assert 872 in _leaf_lines(by_line.get(1390, ())), (
        "dig@1390 no longer sources label74's returned value")
    assert 1201 in _leaf_lines(by_line.get(1440, ())), (
        "dig@1440 no longer sources its callee's returned value")


def test_below_frame_writing_callee_resolves_to_the_written_value(tmp_path):
    """A callee that writes BELOW its own frame must yield the value it WROTE.

    ``frame_bury -2`` under ``proto 1 1`` targets band position
    ``nargs + n = -1`` — the CALLER's residual — and rewrites it, so at runtime
    the caller's ``int 99`` is 7 after the call. Three answers are possible and
    only one is true: the pre-call value (what the clean caller-side reroute
    would say — stale), the callee's exit slot (discarded by the retsub
    truncation), or the residual read AFTER the call past the discarded frame.
    The classifier calls this callee a WRITER (its below-band access is at a
    static position, so the exit sim's widened window models it) and the
    truncation mapping reads ``k - R + h_ret`` off the retsub — the written
    value. Compilers never emit this; a decompiler pulling chain contracts
    must still get it right."""
    teal = tmp_path / "deep_writer.teal"
    teal.write_text(
        "#pragma version 8\n"   # L1
        "int 99\n"              # L2  caller residual (rewritten by the callee!)
        "int 1\n"               # L3  the arg
        "callsub evil\n"        # L4
        "pop\n"                 # L5  pops the return
        "pop\n"                 # L6  pops the deep slot (k=2 > R=1)
        "int 1\n"               # L7
        "return\n"              # L8
        "evil:\n"               # L9
        "proto 1 1\n"           # L10
        "int 7\n"               # L11 the value that lands in the caller
        "frame_bury -2\n"       # L12 nargs+n = -1: below the args
        "int 5\n"               # L13 the return value
        "retsub\n"              # L14
    )
    prog = SSAProgram(str(teal))
    py = prog._pyssa
    cont_key = next((k for k in py._call_pairs), None)
    assert cont_key is not None, "the call should pair (depths stay valid)"
    assert cont_key in py._writer_conts, (
        "a static below-band write is MODELABLE — classifying it hard would "
        "refuse a value the model can derive")
    assert py._sub_below_reach, "the exit sim window was not widened"

    pop_ret = next(a for a in prog.assignments
                   if a.op == "pop" and a.location.line == 5)
    assert any(getattr(i, "line", None) == 13 for i in pop_ret.inputs), (
        "slot k <= R is the VM-enforced return value (int 5 at L13)")
    pop_deep = next(a for a in prog.assignments
                    if a.op == "pop" and a.location.line == 6)
    lines = {getattr(i, "line", None) for i in pop_deep.inputs}
    assert lines == {11}, (
        f"the deep slot must be the value the callee WROTE (int 7 at L11), "
        f"not the stale pre-call 99 at L2 nor a refusal; got lines {lines}")


def test_reroute_into_a_context_insensitive_cycle_terminates(tmp_path):
    """The deep-slot reroute reads the CALLSUB block, skipping the callee entry
    — which used to be the join that broke value-walk cycles created by the
    context-insensitive retsub fan-out (a continuation is statically reachable
    through ANOTHER caller's call). The walk must terminate on such shapes
    (slot-shifting cycles hit the depth cap; a slot-fixed cycle hits the
    ``_reading`` re-entry guard) — a RecursionError here is a contract we
    fail to build at all."""
    teal = tmp_path / "cycle.teal"
    teal.write_text(
        "#pragma version 8\n"
        "callsub f\n"           # outside call: makes the loop region reachable
        "int 1\n"
        "return\n"
        "xsite:\n"
        "callsub f\n"           # in-loop call; its continuation follows
        "pop\n"                 # pops the return (k=1)
        "pop\n"                 # demands k=2 > R -> rerouted through xsite
        "b xsite\n"             # single-pred loop back to the call site
        "f:\n"
        "proto 0 1\n"
        "int 5\n"
        "retsub\n"
    )
    prog = SSAProgram(str(teal))    # must not RecursionError
    assert prog.blocks, "build produced no blocks"


def test_the_blind_spot_is_reported_not_silent(tmp_path, caplog):
    """A read the layer cannot source must SAY so.

    The remaining honest blind class: a continuation of a LEGACY (no ``proto``)
    callee. The pairing deliberately refuses it — a legacy callee declares no
    arity and guessing one would corrupt the frame indexing for every slot —
    so the band has no depth there, the ``frame_dig`` falls back to the narrow
    no-input form, and a pushed local it reads has no source map entry.

    This is the project's own rule applied to a dataflow gap: 0 findings
    because nothing could be resolved must never read the same as 0 findings
    because it is clean. Warned once per program so a corpus sweep stays
    legible."""
    import logging

    teal = tmp_path / "legacy_blind.teal"
    teal.write_text(
        "#pragma version 8\n"
        "callsub outer\n"
        "return\n"
        "outer:\n"
        "proto 0 1\n"
        "int 7\n"
        "callsub legacy\n"
        "frame_dig 0\n"
        "retsub\n"
        "legacy:\n"
        "int 1\n"
        "retsub\n"
    )
    prog = SSAProgram(str(teal))
    blind = frame_unresolved_reads(prog)
    assert {a.location.line for a in blind} == {8}, (
        f"expected the legacy-continuation dig@8 to be the one blind read, "
        f"got {sorted(a.location.line for a in blind)}")

    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.passes.frame_flow"):
        frame_value_sources(prog)
        first = len(caplog.records)
        frame_value_sources(prog)
        assert len(caplog.records) == first, "warned more than once for one program"
    assert first == 1 and "read as CLEAN" in caplog.records[0].getMessage()


def test_a_clean_contract_stays_quiet(caplog):
    """The warning must be a signal, not noise — nothing to report, nothing said."""
    import logging

    probe = PROBES / "app_104988925.teal"
    if not probe.exists():
        pytest.skip("app_104988925 not present")
    prog = SSAProgram(str(probe))
    assert frame_unresolved_reads(prog) == []
    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.passes.frame_flow"):
        frame_value_sources(prog)
    assert not caplog.records
