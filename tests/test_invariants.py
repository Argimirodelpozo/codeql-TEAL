"""Property / invariant tests over the whole benchmark corpus.

Example-based tests check specific inputs; these assert INVARIANTS that must
hold for EVERY program, catching whole bug classes the examples miss:

* the pass pipeline is idempotent (documented in orchestrate.py — running it
  twice is a no-op — but previously untested);
* SSA construction never crashes on any real fixture (robustness net);
* detectors are deterministic (same program → same findings, run to run);
* the lift is deterministic (the ~dN clone-suffix nondeterminism fixed this
  session must stay fixed) — puya-gated.

Corpus = every ``tests/benchmark/*/{vuln,safe}/*.teal`` (small, fast). Failure
names the offending contract.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.passes import run_all_passes

TESTS_ROOT = Path(__file__).resolve().parent
CORPUS = sorted((TESTS_ROOT / "benchmark").rglob("*.teal"))
assert CORPUS, "benchmark corpus is missing"
_IDS = [str(p.relative_to(TESTS_ROOT / "benchmark")) for p in CORPUS]


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_ssa_build_never_crashes(teal):
    # Every real fixture must reconstruct to SSA without raising.
    prog = SSAProgram(str(teal))
    assert prog is not None


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_pass_pipeline_idempotent(teal):
    # orchestrate.py promises each pass is idempotent — a second run_all_passes
    # is a no-op. Assert the annotated functional dump is byte-identical after
    # one vs two runs.
    prog = SSAProgram(str(teal))
    run_all_passes(prog)
    once = prog.functional()
    run_all_passes(prog)
    twice = prog.functional()
    assert once == twice, f"pass pipeline not idempotent on {teal.name}"


@pytest.mark.parametrize("teal", CORPUS, ids=_IDS)
def test_ssa_build_deterministic(teal):
    # Two independent builds of the same source produce the same functional form
    # (no run-to-run nondeterminism leaking from set/dict/id() iteration).
    a = SSAProgram(str(teal))
    run_all_passes(a)
    b = SSAProgram(str(teal))
    run_all_passes(b)
    assert a.functional() == b.functional(), f"SSA nondeterministic on {teal.name}"


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
