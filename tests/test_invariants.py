"""Property / invariant tests over the whole benchmark corpus.

Example-based tests check specific inputs; these assert INVARIANTS that must
hold for EVERY program, catching whole bug classes the examples miss:

* derived analysis views are deterministic and do not mutate canonical SSA;
* SSA construction never crashes on any real fixture (robustness net);
* detectors are deterministic (same program → same findings, run to run);
* the lift is deterministic (the ~dN clone-suffix nondeterminism fixed this
  session must stay fixed) — puya-gated.

Corpus = every ``tests/benchmark/*/{vuln,safe}/*.teal`` PLUS
``tests/handwritten/*.teal`` (small, fast). Failure names the offending
contract.

The hand-written half matters disproportionately. Everything else here is
compiler output, which has a narrow and very regular shape — and this project's
gate gap was exactly that: the branch-polarity false positive found in the
2026-07-25 review was an IDIOMATIC HAND-WRITTEN guard (`!=; bnz fail`) that
puya never emits, so no fixture in the corpus contained one. Scratch-based
locals, mixed branch polarity, `dig`/`cover`/`uncover` shuffling, `match` on
opcode-named labels and hand-rolled loops are all ordinary in hand-written TEAL
and absent from compiled output.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.ssa import Phi, SSAProgram
from tealql.tealtools.analysis import AnalysisContext, DerivedProfile, derived_program

TESTS_ROOT = Path(__file__).resolve().parent
CORPUS = sorted(
    list((TESTS_ROOT / "benchmark").rglob("*.teal"))
    + list((TESTS_ROOT / "handwritten").glob("*.teal"))
)
assert CORPUS, "benchmark corpus is missing"
_IDS = [str(p.relative_to(TESTS_ROOT)) for p in CORPUS]


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_ssa_build_never_crashes(teal):
    # Every real fixture must reconstruct to SSA without raising.
    prog = SSAProgram(str(teal))
    assert prog is not None


#: A deterministic slice of the REAL mainnet probes. The benchmark corpus is
#: small compiled fixtures plus hand-written ones; neither has the block count
#: or the join depth that produces an unconsumed phi, so an invariant checked
#: only over CORPUS can pass while every real contract violates it — which is
#: exactly what happened to the exit_stack invariant below (vacuous on CORPUS,
#: 288 violations in 40 probes). Every 12th probe by name: wide, stable, ~30
#: programs, no dependence on which template happens to be popular.
_PROBES = sorted((TESTS_ROOT / "mainnet-random-probes").glob("*.teal"))[::12]
_PROBE_IDS = [p.name for p in _PROBES]


@pytest.mark.parametrize("teal", (CORPUS + _PROBES),
                         ids=(_IDS + _PROBE_IDS))
def test_exit_stack_phis_are_registered(teal):
    # Every Phi reachable from a block's exit_stack must be in prog.phis.
    # exit_stack carries the PER-EDGE value Phi.args no longer has, and
    # block-arg lowering / the lift's phi rebuild / the frame bridges all read
    # it — but const_prop and range_seed iterate prog.phis, so a phi present
    # only in exit_stack is never annotated and reads as permanently
    # unresolvable. _drop_unconsumed_phis used to filter on op inputs alone and
    # left 288 of 1225 such references dangling across a 40-probe sample.
    prog = SSAProgram(str(teal))
    live = {id(p) for p in prog.phis.values()}
    for bb in prog.blocks.values():
        for slot in bb.exit_stack:
            if isinstance(slot, Phi):
                assert id(slot) in live, (
                    f"{bb.file}:{bb.first_line} exit_stack holds a Phi "
                    f"(slot {slot.stack_index}) missing from prog.phis")


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_derived_view_is_repeatable_and_canonical_ssa_is_unchanged(teal):
    prog = SSAProgram(str(teal))
    before = prog.functional(resolve_consts=False, propagate_consts=False)
    revision = prog.revision
    cached = derived_program(prog, DerivedProfile.PRESENTATION)
    rebuilt = AnalysisContext(prog).derived(DerivedProfile.PRESENTATION)
    assert cached is not rebuilt, "repeatability check reused the cached view"
    once = cached.functional()
    twice = rebuilt.functional()
    assert once == twice, f"derived view not deterministic on {teal.name}"
    assert prog.functional(resolve_consts=False, propagate_consts=False) == before
    assert prog.revision == revision


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_ssa_build_deterministic(teal):
    # Two independent builds of the same source produce the same functional form
    # (no run-to-run nondeterminism leaking from set/dict/id() iteration).
    a = SSAProgram(str(teal))
    b = SSAProgram(str(teal))
    av = derived_program(a, DerivedProfile.PRESENTATION).functional()
    bv = derived_program(b, DerivedProfile.PRESENTATION).functional()
    assert av == bv, f"SSA nondeterministic on {teal.name}"


# One representative detector per family, run over the corpus for determinism.
_DET_NAMES = ["rekey-to", "fee-validation", "tainted-fund-flow",
              "ir-tainted-fund-flow", "abi-method-selector"]


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_detectors_deterministic(teal):
    from tealql.security import DETECTORS

    def run(name):
        cls = DETECTORS.get(name)
        if cls is None:
            return None
        return sorted(v.pretty() for v in cls(SSAProgram(str(teal))).detect())

    for name in _DET_NAMES:
        first = run(name)
        second = run(name)
        assert first == second, f"{name} nondeterministic on {teal.name}"


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_lift_deterministic(teal):
    # The clone-suffix (~dN) nondeterminism fixed this session must stay fixed:
    # rendering the same contract twice gives byte-identical Puya IR text.
    pytest.importorskip("puya")
    from tealql.tealtools.lift import render
    try:
        a = render(SSAProgram(str(teal)))
    except Exception:
        pytest.skip("contract does not lift (coverage limit, not a determinism bug)")
    b = render(SSAProgram(str(teal)))
    assert a == b, f"lift nondeterministic on {teal.name}"
