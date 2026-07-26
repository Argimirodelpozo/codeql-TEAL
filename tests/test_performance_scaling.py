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
    """The smallest and largest mainnet probes — a wide, real size spread."""
    files = sorted(glob.glob(str(TESTS / "mainnet-random-probes" / "*.teal")),
                   key=lambda p: len(Path(p).read_text()))
    if len(files) < 20:
        pytest.skip("mainnet probe corpus not present")
    return Path(files[len(files) // 10]), Path(files[-1])


def _time_detectors(path: Path) -> "tuple[int, float]":
    lines = len(path.read_text().splitlines())
    prog = SSAProgram(str(path))
    prog.propagate_constants()
    names = default_detection_names()
    t0 = time.perf_counter()
    for name in names:
        try:
            DETECTORS[name](prog, file=None).detect()
        except Exception:
            pass                      # a detector fault is not a perf finding
    return lines, time.perf_counter() - t0


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
        t0 = time.perf_counter()
        prog = SSAProgram(str(p))
        prog.propagate_constants()
        return n, time.perf_counter() - t0

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
