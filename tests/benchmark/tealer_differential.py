"""Differential comparison: OUR sec-guide detectors vs Tealer (crytic/tealer).

A ONE-TIME demo / validation tool, NOT part of the usual test suite — Tealer is
an external, slow, occasionally-crashing dependency, so this is run by hand to
produce a snapshot comparison report, not on every CI run. (The file is named
``tealer_differential.py``, not ``test_*.py``, so pytest never collects it.)

For every detector class BOTH tools cover, it runs both over a corpus and diffs
the verdicts. On the ground-truth-labeled benchmark corpus we can say which tool
is RIGHT vs the label; on unlabeled real contracts a disagreement flags a likely
FP/FN in one tool or the other. A tool CRASHING on a contract is a robustness
FAILURE for that tool: a Tealer crash counts as a win for us (we analysed it,
they didn't), and vice-versa.

Tealer is not installed in the project env. Point at it with ``$TEALER`` (path to
the binary) or have ``tealer`` on PATH.

Run:  TEALER=/path/to/tealer python tests/benchmark/tealer_differential.py
      (writes tests/benchmark/TEALER_DIFFERENTIAL.md)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src/analysis"))
sys.path.insert(0, str(REPO / "src"))


# --- the shared vulnerability-class vocabulary ------------------------------
# Both tools cover these classes; the per-tool detector names that map onto each.
# We compare "does ANY detector in the class fire", since the two tools split the
# class differently (e.g. our is-deletable vs unprotected-deletable vs Tealer's).
CLASSES: dict[str, tuple[frozenset, frozenset]] = {
    # class:            (our detector names,                         tealer checks)
    "deletable":        (frozenset({"is-deletable", "unprotected-deletable"}),
                         frozenset({"is-deletable", "unprotected-deletable"})),
    "updatable":        (frozenset({"is-updatable", "unprotected-updatable"}),
                         frozenset({"is-updatable", "unprotected-updatable"})),
    "rekey":            (frozenset({"rekey-to"}), frozenset({"rekey-to"})),
    "close-account":    (frozenset({"close-remainder-to"}),
                         frozenset({"can-close-account"})),
    "close-asset":      (frozenset({"asset-close-to"}),
                         frozenset({"can-close-asset"})),
    "fee":              (frozenset({"fee-validation"}),
                         frozenset({"missing-fee-check"})),
    "group-size":       (frozenset({"group-size-check"}),
                         frozenset({"group-size-check"})),
}


def tealer_bin() -> "str | None":
    return os.environ.get("TEALER") or shutil.which("tealer")


def run_tealer(teal: Path, tealer: str) -> "set[str] | None":
    """The set of Tealer checks that fire on ``teal`` (count > 0), or ``None`` if
    Tealer errored on the contract."""
    try:
        proc = subprocess.run(
            [tealer, "--json", "-", "detect", "--contracts", str(teal)],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None
    out = proc.stdout
    i = out.find("{")
    if i < 0:
        return None
    try:
        data = json.loads(out[i:])
    except json.JSONDecodeError:
        return None
    fired = set()
    for r in data.get("result", []):
        if isinstance(r, dict) and r.get("count", 0) and r.get("check"):
            fired.add(r["check"])
    return fired


def run_ours(teal: Path) -> "set[str] | None":
    """The set of our detector names that fire on ``teal``, or ``None`` if WE
    failed to analyse it at all (we should never — that would be our robustness
    loss, symmetric to a Tealer crash). Scoped by our (opcode-sound) app-vs-
    logicsig classifier so the comparison is apples-to-apples with Tealer's
    auto stateful/stateless scoping."""
    from tealtools.ssa import SSAProgram
    from security import DETECTORS, common
    try:
        prog = SSAProgram(str(teal), verbose=False)
        prog.propagate_constants()
        kind = common.classify_program(prog)
    except Exception:
        return None
    fired = set()
    for det in {d for ours, _ in CLASSES.values() for d in ours}:
        cls = DETECTORS[det]
        applies = getattr(cls, "applies_to", frozenset({"app", "logicsig"}))
        if kind not in applies:
            continue
        try:
            if cls(prog).detect():
                fired.add(det)
        except Exception:
            pass
    return fired


def _class_verdicts(our_fired: set, tealer_fired: "set | None") -> dict:
    """Per class: (we_flag, they_flag) — they_flag is None if Tealer errored."""
    out = {}
    for cls, (ours, theirs) in CLASSES.items():
        we = bool(our_fired & ours)
        they = None if tealer_fired is None else bool(tealer_fired & theirs)
        out[cls] = (we, they)
    return out


def differential(files: list[Path], tealer: str, label: "str | None" = None,
                 jobs: int = 8) -> dict:
    """Compare both tools over ``files`` (Tealer runs concurrently — it's a slow
    subprocess). ``label`` ('vuln'/'safe') is the ground truth when known. A tool
    CRASHING on a contract is a robustness FAILURE for that tool (it produced no
    analysis); per the scoring a Tealer crash is a win for us."""
    def both(f):
        return f, run_ours(f), run_tealer(f, tealer)

    agree = Counter()       # class -> both agree (flag or clean)
    we_only = Counter()     # class -> we flag, Tealer clean
    they_only = Counter()   # class -> Tealer flags, we clean
    tealer_crashes = our_crashes = 0
    disagreements: list = []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for f, ours, theirs in ex.map(both, files):
            if ours is None:
                our_crashes += 1
            if theirs is None:
                tealer_crashes += 1
            if ours is None or theirs is None:
                continue        # can't compare classes; the crash is tallied above
            for cls, (we, they) in _class_verdicts(ours, theirs).items():
                if we == they:
                    agree[cls] += 1
                elif we and not they:
                    we_only[cls] += 1
                    disagreements.append((f.name, cls, "we-flag/tealer-clean", label))
                else:
                    they_only[cls] += 1
                    disagreements.append((f.name, cls, "tealer-flag/we-clean", label))
    return {"agree": agree, "we_only": we_only, "they_only": they_only,
            "tealer_crashes": tealer_crashes, "our_crashes": our_crashes,
            "disagreements": disagreements, "n": len(files)}


def _md_section(title: str, r: dict) -> str:
    n = r["n"]
    out = [f"## {title}", "",
           f"**Robustness** — we analysed **{n - r['our_crashes']}/{n}**, "
           f"Tealer analysed **{n - r['tealer_crashes']}/{n}** "
           f"(Tealer crashed on **{r['tealer_crashes']}** → {r['tealer_crashes']} "
           f"robustness win(s) for us; we crashed on {r['our_crashes']}).", "",
           "| class | agree | we-only | tealer-only |",
           "|---|---:|---:|---:|"]
    for cls in CLASSES:
        out.append(f"| {cls} | {r['agree'][cls]} | {r['we_only'][cls]} | {r['they_only'][cls]} |")
    out.append("")
    if r["disagreements"]:
        out.append(f"<details><summary>{len(r['disagreements'])} class disagreements</summary>\n")
        out.append("| label | contract | class | who flags |")
        out.append("|---|---|---|---|")
        for nm, cls, kind, lbl in r["disagreements"]:
            out.append(f"| {lbl or ''} | {nm} | {cls} | {kind} |")
        out.append("\n</details>")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    tealer = tealer_bin()
    if tealer is None:
        print("tealer not found (set $TEALER or put it on PATH)")
        return 2
    bench = REPO / "tests/benchmark"
    sections: list[str] = []

    # 1) labeled benchmark corpus for the mapped classes (us vs Tealer vs truth)
    for label in ("vuln", "safe"):
        files = []
        for ours, _ in CLASSES.values():
            for det in ours:
                d = bench / det / label
                if d.exists():
                    files += sorted(d.glob("*.teal"))
        if files:
            print(f"benchmark/{label}: {len(files)} files ...", flush=True)
            sections.append(_md_section(
                f"Benchmark corpus — {label} (ground truth = {label})",
                differential(sorted(set(files)), tealer, label)))

    # 2) real mainnet probes (no ground truth; the robustness + agreement headline)
    probes = sorted((REPO / "tests/mainnet-random-probes").rglob("*.teal"))
    if probes:
        print(f"probes: {len(probes)} files ...", flush=True)
        sections.append(_md_section(
            "Real mainnet probes (no ground truth)",
            differential(probes, tealer)))

    body = ("# Tealer differential (one-time demo)\n\n"
            "Our sec-guide detectors vs [crytic/tealer], compared per shared "
            "vulnerability class. Scoped apples-to-apples (both auto-scope "
            "app/logicsig). A tool crashing on a contract is a robustness failure "
            "for that tool. Regenerate: "
            "`TEALER=/path/to/tealer python tests/benchmark/tealer_differential.py`.\n\n"
            + "\n\n".join(sections) + "\n")
    out = bench / "TEALER_DIFFERENTIAL.md"
    out.write_text(body)
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
