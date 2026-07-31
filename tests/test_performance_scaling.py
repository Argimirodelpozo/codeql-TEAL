"""Performance regression gate — on SCALING, not wall-clock.

Nothing in this suite noticed cost. That is a real hole: this project has
shipped quadratic hot spots before (an inner-txn report once took ~28 minutes;
the detector suite ran at 85s until a linear-scan lookup and two missing memos
were fixed this session, halving it). A hot spot reintroduced by a future edit
would simply make CI slower, which nobody reads as a failure.

Wall-clock ceilings are the obvious gate and the wrong one: they encode the
speed of whichever machine wrote them, so they flake on a slow runner and pass
on a fast one no matter what the code does. This gates the SHAPE of the cost
curve instead — run the same analysis over contracts of very different sizes
and require the growth to stay well short of quadratic. That ratio is
machine-independent: a slow runner scales both measurements equally.

Measured when written: 11.4x the lines cost 29.5x the detector time (~n^1.35).
Quadratic on that size ratio would be ~130x, so the bound below sits between
the two with roughly 2x headroom over today.
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

#: Growth allowed, as an exponent of the size ratio. 1.0 is linear, 2.0 is
#: quadratic. Today's ~1.35 passes comfortably; a genuine quadratic does not.
_MAX_EXPONENT = 1.7

#: Absolute per-line ceiling, deliberately loose — it exists only to catch a
#: catastrophic blowup that somehow still scales linearly, not to police speed.
_MAX_MS_PER_LINE = 25.0


def _probe_contracts() -> "tuple[Path, Path]":
    """A small and the largest mainnet probe — a wide, real size spread.

    The small end is the 25th percentile, NOT the 10th. A ratio gate only reads
    as scaling when BOTH measurements are dominated by the analysis; at the 10th
    percentile (~340 lines) the per-program fixed cost is most of the measurement,
    so shrinking that fixed cost inflates the ratio and the gate reports
    "superlinear" for a change that made every absolute time smaller. Measured
    when the lift stopped re-parsing the program: at the 10th percentile the
    apparent exponent moved 1.47 -> 1.75 while the 25th/40th/50th all held at
    1.46-1.56 — the curve had not changed shape, the shortest measurement had
    just stopped measuring the curve. That probe is now only ~50ms and its
    readings swing 1.71-1.83 run to run, i.e. flaky as well as wrong.

    TRADE-OFF, recorded because it is a real loss: the shorter probe was the
    better DISCRIMINATOR. Fault-injecting a dominating n^2 hot spot into one
    detector reads 1.72 against the 10th percentile (fires, barely) but 1.63
    against the 25th (misses, budget 1.7) — a small probe barely feels the
    injected term, so the ratio amplifies it. Between today's 1.53 and an
    injected quadratic's 1.63 there is not enough room for a threshold that is
    neither flaky nor blind, which is a limit of gating the AGGREGATE curve: a
    quadratic component only trips it once it dominates every other cost. A
    per-detector curve is the fix; this gate still catches a whole-suite blowup."""
    files = sorted(glob.glob(str(TESTS / "mainnet-random-probes" / "*.teal")),
                   key=lambda p: len(Path(p).read_text()))
    if len(files) < 20:
        pytest.skip("mainnet probe corpus not present")
    return Path(files[len(files) // 4]), Path(files[-1])


#: Timing samples per measurement. The gates compare a small-vs-large RATIO, so
#: a single skewed sample on EITHER side moves it — and a short measurement is
#: the more fragile of the two.
_REPS = 3


def _cpu_best(work, setup=None) -> float:
    """Best-of-``_REPS`` CPU time for ``work``, with ``setup()`` re-run untimed
    before each repetition.

    Two deliberate choices, both because these gates flaked under a loaded
    machine (twice in one session, and CI runs ``-n auto`` so the contention is
    not hypothetical):

    * ``process_time``, not ``perf_counter`` — it counts THIS process's CPU, so
      a sibling xdist worker saturating a core inflates wall-clock but not this.
      The gate is about work done, not time elapsed.
    * the MINIMUM of several runs — interference only ever adds time, never
      removes it, so the floor is the cleanest estimate of the real cost.

    HAZARD: every repetition must start COLD, which is what ``setup`` is for.
    Reusing one ``SSAProgram`` across repetitions warms its caches, and not
    evenly — measured 0.087→0.032s for a 342-line contract against 4.59→3.08s
    for a 4762-line one. Taking the minimum then deflates the SMALL side ~2x
    harder than the large, inflating the ratio these gates assert on and failing
    a pipeline that never regressed."""
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
def test_detector_cost_stays_well_short_of_quadratic():
    small, large = _probe_contracts()
    n_small, t_small = _time_detectors(small)
    n_large, t_large = _time_detectors(large)

    size_ratio = n_large / max(1, n_small)
    time_ratio = t_large / max(1e-6, t_small)
    budget = size_ratio ** _MAX_EXPONENT

    assert time_ratio <= budget, (
        f"detector cost is growing too fast: {size_ratio:.1f}x the lines "
        f"({n_small} -> {n_large}) cost {time_ratio:.1f}x the time "
        f"(budget {budget:.1f}x at n^{_MAX_EXPONENT}). Quadratic on this ratio "
        f"would be {size_ratio ** 2:.0f}x — something has become superlinear."
    )


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
    """The substrate everything else sits on. A quadratic here is invisible in
    the detector numbers above because it is dwarfed by analysis time."""
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
# The whole-pipeline ratio above catches a CATASTROPHIC regression but is too
# coarse for a component one: restoring the linear-scan scratch lookup this
# session replaced (a genuine O(graph) where O(1) is available) still came in
# at 26.8x against a 62.6x budget, because that path is not what dominates.
# Verified, not assumed — a gate that cannot catch a regression you already
# know about is decoration.
#
# So the lookups that MUST be O(1) are gated directly: their cost is measured
# on a small and a large program, and required not to grow with program size.
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
