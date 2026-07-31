"""The lift leaves its input SSAProgram structurally untouched.

``_prune_dead_assert_edges`` (the one structural mutation the typed lift needs)
is save/restored inside ``_Lifter.build``, so ``build_lifter`` / ``ir_lifter``
lift the scan's OWN program instead of re-parsing a fresh ``SSAProgram`` from
disk — that re-parse was ~45% of the detector lift path, and made programs
without a ``source_path`` unliftable. The SSA-layer detectors read the same
program object, so restore-exactness is load-bearing: the mainnet ratchet is
the at-scale gate, these are the targeted ones.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram

# An always-failing `assert 0` block falling through to a JOIN whose other arm
# is live — the exact shape `_prune_dead_assert_edges` exists for (the dead arm
# contributes a uint64 to a bytes join phi; without the prune the typed lift
# drops the phi). The prune MUST fire on this program for the tests to bite.
_ASSERT_FALSE_JOIN_TEAL = """#pragma version 8
int 1
bnz right
int 5
int 0
assert
join:
len
pushint 3
==
return
right:
byte 0x6162
b join
"""


@pytest.fixture()
def assert_false_prog(tmp_path):
    p = tmp_path / "assert_false_join.teal"
    p.write_text(_ASSERT_FALSE_JOIN_TEAL)
    return SSAProgram(str(p))


def _cfg_snapshot(prog):
    """Structural identity of the CFG: edge lists (order included — successor
    order can be semantic), phi arg identities, assignment count. Annotations
    (const/range/scratch caches) are deliberately NOT part of the snapshot —
    they are the shared annotation layer, not structure."""
    blocks = sorted(prog.blocks.values(), key=lambda b: (b.file, b.first_line))
    return (
        [[id(s) for s in b.successors] for b in blocks],
        [[id(p) for p in b.predecessors] for b in blocks],
        {id(ph): [id(a) for a in ph.args] for ph in prog.phis.values()},
        len(prog.assignments),
    )


def test_prune_returns_a_real_undo_and_restores_exactly(assert_false_prog):
    """Unit: the prune fires on the fixture (a no-op prune would make the whole
    file vacuous) and its undo record inverts it position-exactly."""
    from tealql.tealtools.lift.lift import (_prune_dead_assert_edges,
                                            _restore_pruned_edges)
    prog = assert_false_prog
    before = _cfg_snapshot(prog)
    undo = _prune_dead_assert_edges(prog)
    assert undo[0], "prune did not fire — fixture no longer exercises the path"
    assert _cfg_snapshot(prog) != before, "prune fired but changed nothing"
    _restore_pruned_edges(undo)
    assert _cfg_snapshot(prog) == before


def test_lift_restores_input_cfg(assert_false_prog):
    """End-to-end: a successful lift() hands the program back bit-identical in
    structure — the contract build_lifter/ir_lifter rely on to share the prog."""
    from tealql.tealtools.lift.lift import lift
    prog = assert_false_prog
    prog.propagate_constants()               # entry points run this pre-lift
    before = _cfg_snapshot(prog)
    pre = lift(prog)
    assert pre is not None
    assert _cfg_snapshot(prog) == before
    # And the lift stays repeatable on the restored program.
    assert lift(prog) is not None
    assert _cfg_snapshot(prog) == before


@pytest.mark.parametrize("probe", [
    "app_104988925.teal", "app_1050114602.teal", "app_100742517.teal"])
def test_lift_restores_input_on_real_probes(probe):
    """The restore holds on real mainnet programs, not just the synthetic."""
    from tealql.tealtools.lift.lift import lift
    from tealql.tealtools.errors import LiftError
    path = Path(__file__).resolve().parent / "mainnet-random-probes" / probe
    if not path.exists():
        pytest.skip(f"{probe} not present")
    prog = SSAProgram(str(path))
    prog.propagate_constants()
    before = _cfg_snapshot(prog)
    try:
        lift(prog)
    except LiftError:
        pass                                 # restore must hold on failure too
    assert _cfg_snapshot(prog) == before


def _wiring_snapshot(prog):
    """Consumer wiring: what ``propagate_inputs`` / ``propagate_stack_shuffles``
    rewrite. Distinct from ``_cfg_snapshot`` (edges) — this is the def-use side."""
    return (
        [[id(v) for v in a.inputs] for a in prog.assignments],
        [a.shuffled for a in prog.assignments],
        {id(p): [id(v) for v in p.args] for p in prog.phis.values()},
    )


def test_byte_taint_validation_does_not_rewire_the_caller(tmp_path):
    """``byte_taint(validate=True)`` needs the input/shuffle unification, but must
    not leave it on a program the caller shares — the IR detectors run it on the
    very program the SSA detectors read (``ir_lifter`` lifts in place).

    Leaking it re-pointed consumers at coarse stack-slot merge phis, and a
    MAY-semantics walker followed those into unrelated producers: it invented an
    ``unsafe-division-order`` finding whose `/` reached the `*` only through a
    30-arg phi mixing bytes and uint64 producers. Annotations may cross that
    boundary (they only refine); a rewiring may not."""
    from tealql.tealtools.dataflow.byte_taint import byte_taint
    probe = Path(__file__).resolve().parent / "mainnet-random-probes" / "app_3350348253.teal"
    if not probe.exists():
        pytest.skip("app_3350348253 not present")
    prog = SSAProgram(str(probe))
    prog.propagate_constants()
    before = _wiring_snapshot(prog)
    res = byte_taint(prog, validate=True)
    assert res is not None
    assert _wiring_snapshot(prog) == before, \
        "byte_taint(validate=True) leaked its input/shuffle unification"
    assert not prog._inputs_propagated and not prog._shuffles_propagated
    # A program that already carries the unification keeps it (not ours to undo).
    prog.propagate_inputs()
    prog.propagate_stack_shuffles()
    owned = _wiring_snapshot(prog)
    byte_taint(prog, validate=True)
    assert _wiring_snapshot(prog) == owned
    assert prog._inputs_propagated and prog._shuffles_propagated


def test_entry_points_lift_the_shared_program(assert_false_prog):
    """build_lifter/ir_lifter now lift prog ITSELF (no fresh re-parse): the
    cached lifter's .prog is the very object handed in."""
    from tealql.tealtools.lift import build_lifter
    prog = assert_false_prog
    before = _cfg_snapshot(prog)
    lifter = build_lifter(prog)
    assert lifter is not None and lifter.prog is prog
    assert prog._ir_lifter is lifter
    assert _cfg_snapshot(prog) == before

    from tealql.security._itxn_taint import ir_lifter
    del prog._ir_lifter                      # bust the shared cache
    lifter2 = ir_lifter(prog)
    assert lifter2 is not None and lifter2.prog is prog
    assert _cfg_snapshot(prog) == before
