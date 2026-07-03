"""Generate the per-detector precision/recall table into ``docs/PRECISION.md``.

    python -m tests.gen_precision

Runs the ground-truth benchmark (:mod:`tests.test_benchmark`) and writes a
markdown report — the published, regenerable version of the numbers the
benchmark test pins. Run it after growing the corpus or an intentional detector
change (the same time you update ``_BASELINE``).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "PRECISION.md"

# Runnable as `python -m tests.gen_precision` (no pytest/conftest): put the
# source packages + this dir on the path the way conftest does under pytest.
for _p in (REPO / "src", Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from tealql.security import confidence_of, severity_of  # noqa: E402
from test_benchmark import Score, run_benchmark   # noqa: E402

_CAVEAT = """\
> **Read this first.** These numbers are measured on a **small, curated**
> ground-truth corpus (`tests/benchmark/<detector>/{vuln,safe}/`), not on a
> random sample of real-world contracts. A perfect score means the detector
> behaves as intended on the cases we wrote to characterise it — it is a
> **regression gate and a specification**, not a field false-positive rate.
> Where a detector has a known blind spot, the corpus encodes it as a real
> FN/FP so the limitation is a number, not a footnote. Grow the corpus (see
> `tests/benchmark/README.md`) to make the numbers more representative.
"""


def _md_table(scores: dict[str, Score]) -> str:
    rows = ["| Detector | Severity | Confidence | TP | FP | FN | TN | Precision | Recall | F1 |",
            "| --- | --- | --- | --: | --: | --: | --: | --: | --: | --: |"]
    agg = Score()
    for det in sorted(scores):
        s = scores[det]
        agg = Score(agg.tp + s.tp, agg.fp + s.fp, agg.fn + s.fn, agg.tn + s.tn)
        rows.append(
            f"| `{det}` | {severity_of(det)} | {confidence_of(det)} | "
            f"{s.tp} | {s.fp} | {s.fn} | {s.tn} | "
            f"{s.precision:.2f} | {s.recall:.2f} | {s.f1:.2f} |")
    rows.append(
        f"| **overall** | | | **{agg.tp}** | **{agg.fp}** | **{agg.fn}** | "
        f"**{agg.tn}** | **{agg.precision:.2f}** | **{agg.recall:.2f}** | "
        f"**{agg.f1:.2f}** |")
    return "\n".join(rows)


def build_report() -> str:
    scores = run_benchmark()
    n_vuln = sum(s.tp + s.fn for s in scores.values())
    n_safe = sum(s.fp + s.tn for s in scores.values())
    return (
        "# Detector precision / recall\n\n"
        f"{len(scores)} detectors · {n_vuln} vulnerable + {n_safe} safe "
        "ground-truth cases.\n\n"
        f"{_CAVEAT}\n"
        f"{_md_table(scores)}\n\n"
        "_Regenerate with_ `python -m tests.gen_precision`.\n"
    )


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(build_report())
    print(f"wrote {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
