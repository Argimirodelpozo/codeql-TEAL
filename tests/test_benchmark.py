"""Detector precision/recall benchmark — detector quality as a measured number.

A GROUND-TRUTH-labeled corpus under ``tests/benchmark/<detector>/{vuln,safe}/*.teal``:
a ``vuln`` case is a contract the detector SHOULD flag, a ``safe`` case one it
should NOT. The harness runs each registered detector against its cases and scores
precision / recall / F1 against that truth — so a detector change is measured, not
guessed, and known limitations surface as a number (e.g. tainted-fund-flow's
param-fed false-negative shows up as recall < 1.0).

See the table:   pytest tests/test_benchmark.py -s
"""
from dataclasses import dataclass
from pathlib import Path

from tealtools.ssa import SSAProgram
from security import DETECTORS

BENCH = Path(__file__).resolve().parent / "benchmark"


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _fires(detector: str, teal: Path) -> bool:
    """Does ``detector`` flag ``teal`` (>=1 finding)? The benchmark measures
    detector LOGIC on per-detector-curated fixtures; mode scoping (app vs
    logicsig) is a deployment concern declared in the detection-options config,
    not exercised here."""
    prog = SSAProgram(str(teal), verbose=False)
    prog.propagate_constants()
    return len(DETECTORS[detector](prog).detect()) > 0


def _detectors_with_corpus() -> list[str]:
    # A detector corpus dir has a vuln/ and/or safe/ subdir; skip anything else
    # under tests/benchmark/ (e.g. __pycache__ from the Tealer-differential tool).
    return sorted(
        d.name for d in BENCH.iterdir()
        if d.is_dir() and ((d / "vuln").is_dir() or (d / "safe").is_dir())
    )


def run_benchmark() -> dict[str, Score]:
    scores: dict[str, Score] = {}
    for det in _detectors_with_corpus():
        s = Score()
        for case in sorted((BENCH / det / "vuln").glob("*.teal")):
            if _fires(det, case):
                s.tp += 1           # correctly flagged a vulnerable contract
            else:
                s.fn += 1           # MISSED a real vulnerability
        for case in sorted((BENCH / det / "safe").glob("*.teal")):
            if _fires(det, case):
                s.fp += 1           # false alarm on a safe contract
            else:
                s.tn += 1
        scores[det] = s
    return scores


def _table(scores: dict[str, Score]) -> str:
    head = f"{'detector':22} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  {'prec':>5} {'rec':>5} {'F1':>5}"
    lines = [head, "-" * len(head)]
    agg = Score()
    for det, s in scores.items():
        agg = Score(agg.tp + s.tp, agg.fp + s.fp, agg.fn + s.fn, agg.tn + s.tn)
        lines.append(f"{det:22} {s.tp:3} {s.fp:3} {s.fn:3} {s.tn:3}  "
                     f"{s.precision:5.2f} {s.recall:5.2f} {s.f1:5.2f}")
    lines.append("-" * len(head))
    lines.append(f"{'OVERALL':22} {agg.tp:3} {agg.fp:3} {agg.fn:3} {agg.tn:3}  "
                 f"{agg.precision:5.2f} {agg.recall:5.2f} {agg.f1:5.2f}")
    return "\n".join(lines)


# Per-detector confusion baseline (tp, fp, fn, tn). Pins current behaviour so any
# regression (a new FP, a lost TP) fails the test. Update DELIBERATELY when the
# corpus grows or a detector intentionally changes -- and say why.
#
# tainted-fund-flow now scores recall 1.0: param_fed_callee.teal (the proto-frame
# param flow the SSA def-use can't see) is rescued by the IR lift's
# interprocedural fund-flow, wired into the detector as a callsub-gated supplement.
_BASELINE: dict[str, tuple[int, int, int, int]] = {
    "abi-method-selector": (1, 0, 0, 1),
    "arbitrary-inner-appcall": (4, 0, 0, 4),
    "arbitrary-inner-asset": (2, 0, 0, 3),
    "asset-close-to": (2, 0, 0, 3),
    "asset-id-validation": (1, 0, 0, 2),
    "box-key": (3, 0, 0, 2),
    "close-remainder-to": (2, 0, 0, 1),
    "constant-condition": (3, 0, 0, 3),
    "delete-funds-check": (2, 0, 0, 1),
    "fee-validation": (1, 0, 0, 1),
    "group-size-check": (1, 0, 0, 2),
    "hardcoded-min-balance": (1, 0, 0, 1),
    "inner-txn-close-rekey": (1, 0, 0, 1),
    "inner-txn-fee": (1, 0, 0, 1),
    "ir-tainted-fund-flow": (5, 0, 0, 5),
    "is-deletable": (1, 0, 0, 1),
    "is-updatable": (1, 0, 0, 1),
    "lease-validation": (1, 0, 0, 1),
    "partial-tainted-fund-flow": (3, 0, 0, 3),
    "rekey-to": (3, 0, 0, 2),
    "tainted-fund-flow": (4, 0, 0, 4),
    "timelock-upgrade": (1, 0, 0, 1),
    "tx-type-check": (1, 0, 0, 1),
    "unprotected-deletable": (1, 0, 0, 1),
    "unprotected-updatable": (1, 0, 0, 1),
    "unsafe-division-order": (3, 0, 0, 3),
    "unsafe-lsig-args": (1, 0, 0, 1),
    "unvalidated-group-sibling": (4, 0, 0, 5),
}


def test_benchmark_baseline(capsys):
    scores = run_benchmark()
    with capsys.disabled():
        print("\n" + _table(scores) + "\n")
    actual = {d: (s.tp, s.fp, s.fn, s.tn) for d, s in scores.items()}
    assert actual == _BASELINE, (
        "detector behaviour changed vs the benchmark baseline; review the new "
        "FP/FN and update _BASELINE intentionally"
    )
