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
def test_no_written_local_read_is_left_without_a_source(teal):
    """THE soundness property: a ``frame_dig`` reading a slot version some
    ``frame_bury`` WROTE, and carrying no band (narrow fallback, so no inputs),
    must be reconnected by the frame map. 394 such reads over a 40-probe sample
    were previously unreachable from their ``frame_bury``.

    Scoped to version > 0 deliberately. A version-0 read takes the slot's
    INITIALISER, which no bury produced — its value is whatever the routine
    prologue pushed, and recovering that needs the very band arithmetic the
    narrow fallback could not do. Compiled output initialises locals with
    constants (``bytec_0 ""`` / ``intc_0 0``), so those reads are clean in
    practice; hand-written TEAL could park a live value there, which is the
    residual. Params are likewise not asserted at 100%: ``frame_param_sources``
    documents that it skips a call site whose ``exit_stack`` was capped (21 of
    530), and states that absence must be read as unknown, not clean."""
    from tealql.tealtools.passes.frame_resolution import resolve

    prog = SSAProgram(teal)
    written = set()                       # frame_dig outputs reading a WRITTEN version
    for _sub, fr in resolve(prog).items():
        for out, key in fr.dig_local.items():
            if key[1] > 0:
                written.add(id(out))
    covered = {id(k) for k in frame_value_sources(prog)}
    orphans = [a for n, a in _frame_digs(prog)
               if n >= 0 and not a.inputs and a.outputs
               and id(a.outputs[0]) in written
               and id(a.outputs[0]) not in covered]
    assert not orphans, (
        f"{len(orphans)} frame_dig read(s) of a WRITTEN local have neither a band "
        f"nor a frame source, so they read as clean: "
        f"{[f'{a.location.file}:{a.location.line}' for a in orphans[:5]]}")


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
