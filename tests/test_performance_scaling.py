"""Performance regression gate — on SCALING, not wall-clock.

This project has shipped quadratic hot spots before (an inner-txn report once
took ~28 minutes). One reintroduced by a future edit just makes CI slower,
which nobody reads as a failure.

Wall-clock ceilings are the obvious gate and the wrong one: they encode the
speed of whichever machine wrote them. What is gated here is an absolute
per-line ceiling (catastrophic blowup only) and the COMPONENT lookups that must
be O(1) — each validated by restoring the old implementation and confirming the
gate fires.

A whole-pipeline ratio gate lived here and was REMOVED: fault-injecting a
dominating n^2 hot spot moved it 1.53 -> 1.63 against a 1.7 budget, missing the
regression it existed for, while machine load pushed it past that same budget
three times on unchanged code. An aggregate only moves once a quadratic
component dominates every other cost. Per-detector curves are the right shape
if that question is ever worth re-answering.
"""
from __future__ import annotations

import glob
import time
from pathlib import Path

import pytest

from tealql.security import DETECTORS
from tealql.security.scan import default_detection_names
from tealql.tealtools.ssa import SSAProgram

TESTS = Path(__file__).resolve().parent

#: Growth allowed for SSA construction, as an exponent of the size ratio (1.0 =
#: linear, 2.0 = quadratic). Deliberately loose — see the module note on why an
#: aggregate ratio cannot be tightened into a real discriminator.
_MAX_EXPONENT = 1.7

#: Absolute per-line ceiling, deliberately loose — it exists only to catch a
#: catastrophic blowup that somehow still scales linearly, not to police speed.
_MAX_MS_PER_LINE = 25.0


def _probe_contracts() -> "tuple[Path, Path]":
    """A small and the largest mainnet probe — a wide, real size spread.

    The small end is the 25th percentile, NOT the 10th. A ratio only reads as
    scaling when BOTH measurements are dominated by the analysis; at the 10th
    percentile (~340 lines) per-program fixed cost is most of the measurement,
    so shrinking that fixed cost inflates the ratio and reports "superlinear"
    for a change that made every absolute time smaller."""
    files = sorted(glob.glob(str(TESTS / "mainnet-random-probes" / "*.teal")),
                   key=lambda p: len(Path(p).read_text()))
    if len(files) < 20:
        pytest.skip("mainnet probe corpus not present")
    return Path(files[len(files) // 4]), Path(files[-1])


#: Timing samples per measurement. A single skewed sample on either side moves
#: a ratio, and the short measurement is the more fragile of the two.
_REPS = 3


def _cpu_best(work, setup=None) -> float:
    """Best-of-``_REPS`` CPU time for ``work``, with ``setup()`` re-run untimed
    before each repetition.

    Two deliberate choices, both because these gates flaked on a loaded machine
    (CI runs ``-n auto``, so contention is not hypothetical):

    * ``process_time``, not ``perf_counter`` — it counts THIS process's CPU, so
      a sibling xdist worker saturating a core inflates wall-clock but not this.
    * the MINIMUM of several runs — interference only ever adds time.

    HAZARD: every repetition must start COLD, which is what ``setup`` is for.
    Reusing one ``SSAProgram`` warms its caches unevenly — measured 0.087→0.032s
    for a 342-line contract against 4.59→3.08s for a 4762-line one — which
    deflates the SMALL side ~2x harder and inflates any ratio built on it."""
    best = float("inf")
    for _ in range(_REPS):
        state = setup() if setup is not None else None
        t0 = time.process_time()
        work(state) if setup is not None else work()
        best = min(best, time.process_time() - t0)
    return best


def _time_detectors(path: Path) -> "tuple[int, float]":
    lines = len(path.read_text().splitlines())
    names = default_detection_names()

    def _fresh():                     # untimed: a COLD program per repetition
        prog = SSAProgram(str(path))
        prog.propagate_constants()
        return prog

    def _run(prog):
        for name in names:
            try:
                DETECTORS[name](prog, file=None).detect()
            except Exception:
                pass                  # a detector fault is not a perf finding

    return lines, _cpu_best(_run, setup=_fresh)


@pytest.mark.slow
def test_no_catastrophic_absolute_cost():
    """A blowup that somehow scales linearly still has to be caught."""
    _small, large = _probe_contracts()
    lines, elapsed = _time_detectors(large)
    ms_per_line = elapsed * 1000 / max(1, lines)
    assert ms_per_line <= _MAX_MS_PER_LINE, (
        f"{ms_per_line:.2f} ms/line on a {lines}-line contract "
        f"(ceiling {_MAX_MS_PER_LINE})"
    )


@pytest.mark.slow
def test_ssa_construction_scales():
    """The substrate everything else sits on — a quadratic here is invisible in
    detector timings because analysis time dwarfs it.

    HAZARD: this is an aggregate ratio, the shape the module note warns about.
    It is kept only because SSA construction is ONE component rather than a
    whole pipeline, so a quadratic in it does dominate its own measurement."""
    small, large = _probe_contracts()

    def _build(p: Path):
        n = len(p.read_text().splitlines())

        def _work():
            prog = SSAProgram(str(p))
            prog.propagate_constants()

        return n, _cpu_best(_work)

    n_small, t_small = _build(small)
    n_large, t_large = _build(large)
    size_ratio = n_large / max(1, n_small)
    time_ratio = t_large / max(1e-6, t_small)
    assert time_ratio <= size_ratio ** _MAX_EXPONENT, (
        f"SSA construction: {size_ratio:.1f}x lines cost {time_ratio:.1f}x time"
    )


# ---------------------------------------------------------------------------
# Component-level gates
#
# The lookups that MUST be O(1) are gated directly: measured on a small and a
# large program, and required not to grow with program size. This is the shape
# that works — an aggregate gate could not catch a regression it was pointed
# at (restoring the linear-scan scratch lookup came in at 26.8x against a 62.6x
# aggregate budget, because that path is not what dominates).
# ---------------------------------------------------------------------------


def _scratch_probe_contracts() -> "tuple[Path, Path]":
    """Smallest and largest probes that actually CONTAIN scratch loads.

    The generic pair does not do: the small end often has no `load` at all, and
    the gate then SKIPS — which reads as a pass in the summary while measuring
    nothing. Selected by content, not by size alone."""
    files = [Path(f) for f in glob.glob(str(TESTS / "mainnet-random-probes" / "*.teal"))]
    with_loads = [f for f in files
                  if any(ln.strip().startswith("load ")
                         for ln in f.read_text(errors="replace").splitlines())]
    if len(with_loads) < 10:
        pytest.skip("not enough scratch-using probes")
    with_loads.sort(key=lambda p: len(p.read_text()))
    return with_loads[0], with_loads[-1]


def _lookup_cost(path: Path, reps: int = 400) -> float:
    """Seconds for ``reps`` scratch-store lookups on ``path``'s biggest load."""
    from tealql.security._value_flow import _scratch_stores_for

    prog = SSAProgram(str(path))
    prog.propagate_constants()
    loads = [o for a in prog.assignments if a.op == "load"
             for o in a.outputs if getattr(o, "defined_by", None) is not None]
    if not loads:
        pytest.skip(f"{path.name} has no scratch loads")
    # The WORST-CASE load, not the first. A linear scan RETURNS ON FIRST MATCH,
    # so probing an early load costs the same whatever the graph size and the
    # gate measures nothing (verified: 1.6x for a scan that is genuinely
    # O(graph)). The last load is the one a scan has to walk the graph to find.
    var = max(loads, key=lambda o: o.line)
    _scratch_stores_for(prog, var)                 # warm the index
    t0 = time.perf_counter()
    for _ in range(reps):
        _scratch_stores_for(prog, var)
    return time.perf_counter() - t0


@pytest.mark.slow
def test_scratch_store_lookup_does_not_scale_with_program_size():
    """`_scratch_stores_for` is called from inside two nested loops (the MUST-flow
    walk and the user-input taint fixpoint). It used to LINEAR-SCAN the op graph
    — ~0.25 ms per lookup on a real contract — and is now indexed.

    An O(1) lookup costs the same on a 350-line and a 4000-line contract; the
    linear scan costs 8.8x more on the worst-case load. The bound sits between,
    and both numbers were MEASURED by restoring the old implementation — a gate
    that cannot catch a regression you already know about is decoration."""
    small, large = _scratch_probe_contracts()
    t_small = _lookup_cost(small)
    t_large = _lookup_cost(large)
    ratio = t_large / max(1e-9, t_small)
    assert ratio <= 4.0, (
        f"scratch-store lookup cost grew {ratio:.1f}x between a "
        f"{len(small.read_text().splitlines())}-line and a "
        f"{len(large.read_text().splitlines())}-line contract — it is scanning, "
        "not indexing"
    )
