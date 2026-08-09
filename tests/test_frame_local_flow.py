"""A value parked in a frame slot must not lose its taint on the way back out.

Canonical SSA now records exact frame reads as ordinary inputs. Bottom-anchor
ambiguity can still leave an honest gap, so the compatibility provenance API
reconstructs parameter and local sources while ``frame_gap_sources`` filters
that map to only edges SSA does not already carry. These tests pin both the
external complete map and the smaller map used by MAY consumers.
"""
import glob
import random
from pathlib import Path

import pytest

from tealql.tealtools.avm import op_arity
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.relations import (
    frame_gap_sources,
    frame_local_sources,
    frame_param_sources,
    frame_unresolved_reads,
    frame_value_sources,
    shared_execution_blocks,
    unresolved_call_results,
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


def test_gap_map_omits_sources_already_carried_by_ssa():
    prog = SSAProgram.from_text(
        "#pragma version 8\n"
        "pushint 7\n"
        "callsub use\n"
        "pushint 1\n"
        "return\n"
        "use:\n"
        "proto 1 0\n"
        "frame_dig -1\n"
        "pop\n"
        "retsub\n",
        name="frame-gap.teal",
    )
    full = frame_value_sources(prog)
    assert full, "fixture must exercise the compatibility source API"
    gap = frame_gap_sources(prog)
    assert gap == {}, (
        "a resolved frame input was redundantly reintroduced as an implicit edge")
    assert frame_gap_sources(prog) is gap, "the shared MAY bridge must be cached"


def test_may_consumers_use_the_gap_map_with_local_sources():
    """The filtered bridge must retain unresolved local edges.

    The dataflow engine, taint graph and byte taint are wired by import name;
    byte taint exposes the selected map, so assert its gap still covers a real
    local read instead of falling back to parameter-only provenance.
    """
    from tealql.tealtools.dataflow.byte_taint import byte_taint

    probe = PROBES / "app_3300088574.teal"
    if not probe.exists():
        pytest.skip("app_3300088574 not present")
    prog = SSAProgram(str(probe))
    locals_ = frame_local_sources(prog)
    assert locals_, "fixture no longer has local frame reads — pick another probe"
    res = byte_taint(prog)
    # Analysis results are produced on an isolated SSA snapshot.  SSAVars have
    # stable structural identity across snapshots, so callers must not depend
    # on Python object identity here.
    assert set(res.frame_src) & set(locals_), (
        "byte_taint's frame gap carries no local frame reads — an unresolved "
        "value read out of a frame slot would therefore read as clean")


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
    # L1323, NOT L1201. label77 is `proto 1 1` and ends
    # `frame_dig 0; concat; frame_bury 0; retsub` — a proto'd retsub returns
    # FRAME SLOT 0, which is what that `frame_bury 0` wrote (the concat at
    # L1323). L1201 is `extract 186 32`, an unrelated leftover deep in the
    # callee's working stack, and this assertion pinned it only because the
    # simulator used to read the return off the STACK TOP. The blind spot was
    # closed to the wrong value.
    assert 1323 in _leaf_lines(by_line.get(1440, ())), (
        "dig@1440 no longer sources its callee's returned value")


def test_below_band_frame_ops_cannot_run_so_are_never_read_as_clean(tmp_path):
    """A ``frame_bury`` targeting below its own args is DEAD, and must not be
    mistaken for a modelable write.

    Measured on a live AVM (2026-08-01): the node rejects this at RUNTIME —
    "frame_bury -2 in sub with 1 args" — not merely at assembly, so no such
    program can execute. An earlier draft read the "frame is a convention"
    docs as licence to model the write and thread the caller's residual
    through the retsub; that machinery described a shape with no runtime
    meaning, and is gone. What the frame really does NOT bound is PLAIN stack
    ops (`cover` reaching under the band runs and permutes caller values) —
    that is the case ``_classify_call_effects`` exists for.

    The requirement that survives: build it, lift it, and never call it
    clean."""
    teal = tmp_path / "dead_writer.teal"
    teal.write_text(
        "#pragma version 8\n"
        "int 99\nint 1\ncallsub evil\npop\npop\nint 1\nreturn\n"
        "evil:\nproto 1 1\nint 7\nframe_bury -2\nint 5\nretsub\n"
    )
    prog = SSAProgram(str(teal))
    py = prog._pyssa
    assert py._call_pairs, "the call should still pair (depths stay valid)"
    assert py._unsafe_callee_blocks, (
        "an out-of-frame frame_bury must not leave the continuation reading the "
        "caller's pre-call value as if the callee were clean")
    pop_deep = next(a for a in prog.assignments
                    if a.op == "pop" and a.location.line == 6)
    assert not pop_deep.inputs, "the withdrawn deep slot must refuse"


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

    The honest blind class: a read of a slot a CLOBBERING callee sat under.
    ``evil`` declares ``proto 1 1`` and then ``cover 3`` reaches four deep — the
    AVM does not bound plain stack ops by the frame, so this runs and permutes
    the caller's values. The caller's residual is therefore withdrawn, and the
    ``frame_dig`` that reads into it has nothing to take.

    This is the project's own rule applied to a dataflow gap: 0 findings
    because nothing could be resolved must never read the same as 0 findings
    because it is clean. Warned once per program so a corpus sweep stays
    legible.

    NB the fixture used to be a LEGACY-callee continuation. That gap is closed —
    a legacy callee's arity is now inferred rather than refused — so pinning it
    would pin an absence of capability instead of the reporting contract."""
    import logging

    teal = tmp_path / "clobbered_blind.teal"
    teal.write_text(
        "#pragma version 8\n"
        "callsub outer\n"
        "return\n"
        "outer:\n"
        "proto 0 1\n"
        "int 99\n"
        "int 1\n"
        "callsub evil\n"
        "frame_dig 0\n"
        "retsub\n"
        "evil:\n"
        "proto 1 1\n"
        "cover 3\n"
        "retsub\n"
    )
    prog = SSAProgram(str(teal))
    blind = frame_unresolved_reads(prog)
    assert {a.location.line for a in blind} == {9}, (
        f"expected the clobbered-residual dig@9 to be the one blind read, "
        f"got {sorted(a.location.line for a in blind)}")

    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.ssa.relations"):
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
    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.ssa.relations"):
        frame_value_sources(prog)
    assert not caplog.records


#: Call-result slots the builder cannot name, over the 231 distinct probes.
#: A CEILING at today's measurement, not a target — 0 is the target.
_UNRESOLVED_CALL_RESULTS = 15

#: Ops whose operand list is SHORTER than their canonical arity, same corpus.
#: Convention-independent (it asks "did the builder name every operand?"), so it
#: is comparable across stack models: main measures 516 of 97,077 here, this
#: model 22. That gap is the point of the model change, and the ceiling stops it
#: quietly closing back up.
_MISSING_OPERANDS = 22

_ARITY_SKIP = frozenset({"frame_dig", "frame_bury", "callsub", "retsub", "proto",
                         "intcblock", "bytecblock", "return", "err"})


def _corpus():
    from tests.mainnet_ratchet import distinct_probes
    probes = distinct_probes()
    if len(probes) < 100:
        pytest.skip("mainnet probe corpus not present")
    return probes


@pytest.mark.slow
def test_the_builder_names_what_a_call_returns():
    """A ``proto A R`` callee promises R values; a ``None`` in those slots is a
    value no consumer can see, and it reads as CLEAN.

    This assertion did not exist while a recursive callee's result was ``None``
    in 15 of these very contracts — they lifted, the live-AVM dryrun matched
    outcome for outcome, and the suite was green. A downstream prover found it.
    """
    total, worst = 0, []
    for _h, path in _corpus():
        try:
            prog = SSAProgram(str(path), strict=False)
        except Exception:
            continue
        n = len(unresolved_call_results(prog))
        total += n
        if n:
            worst.append((path.name, n))
    worst.sort(key=lambda x: -x[1])
    assert total <= _UNRESOLVED_CALL_RESULTS, (
        f"{total} call-result slot(s) have no value (ceiling "
        f"{_UNRESOLVED_CALL_RESULTS}) — a call whose result the builder cannot "
        f"name is a silent hole:\n  " + "\n  ".join(f"{n}: {c}" for n, c in worst[:8]))


@pytest.mark.slow
def test_the_builder_names_every_operand_it_can():
    """``len(inputs) < canonical arity`` means an operand the builder could not
    name — ``_build_assignments`` drops a ``None`` rather than keeping a hole.

    Deliberately asks a question that does NOT depend on the stack model, so the
    number stays meaningful across one. Frame and call ops are excluded because
    their arity IS model-specific."""
    total = examined = 0
    by_op: dict = {}
    for _h, path in _corpus():
        try:
            prog = SSAProgram(str(path), strict=False)
        except Exception:
            continue
        for a in prog.assignments:
            if a.op in _ARITY_SKIP:
                continue
            n_in, _ = op_arity(a.op, a.immediates)
            if n_in <= 0:
                continue
            examined += 1
            if len(a.inputs) < n_in:
                total += 1
                by_op[a.op] = by_op.get(a.op, 0) + 1
    assert examined > 50_000, f"metric went vacuous ({examined} ops examined)"
    assert total <= _MISSING_OPERANDS, (
        f"{total} op(s) of {examined} are missing an operand (ceiling "
        f"{_MISSING_OPERANDS}) — the builder stopped naming values it used to: "
        f"{sorted(by_op.items(), key=lambda kv: -kv[1])[:8]}")


#: Blocks executed by more than one routine, over the 231 distinct probes.
#: A CEILING. Not a defect to drive to zero — a shared tail is legal TEAL — but
#: the simulation runs such a block ONCE, on its owner's stack, so its operands
#: are the wrong values for the other caller. It must stay listed.
_SHARED_EXECUTION_BLOCKS = 10


@pytest.mark.slow
def test_shared_tails_are_listed_not_silent():
    """A block two routines branch into is executed by both and simulated once.

    That is context-insensitivity, the same class as `not_function_shaped`, and
    the same rule applies: list it. What must NOT happen is the operands inside
    reading like any other resolved value, because for one of the two callers
    they are simply the wrong ones.

    It is 10 blocks of 29,786 (0.03%), which is why the two partitioners behind
    it are NOT being converged — `pyblock_partition` runs before the
    `SSAProgram` exists and cannot reuse the corrected policy, so converging is
    a semantic change, and this is what it would buy.
    """
    total, worst = 0, []
    for _h, path in _corpus():
        try:
            prog = SSAProgram(str(path), strict=False)
        except Exception:
            continue
        n = len(shared_execution_blocks(prog))
        total += n
        if n:
            worst.append((path.name, n))
    worst.sort(key=lambda x: -x[1])
    assert total <= _SHARED_EXECUTION_BLOCKS, (
        f"{total} block(s) are executed by more than one routine (ceiling "
        f"{_SHARED_EXECUTION_BLOCKS}) — each is simulated on ONE owner's stack, "
        f"so the other caller's operands there are wrong: {worst[:6]}")
