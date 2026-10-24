"""Behaviour fingerprint: every user-visible analysis output over the real corpora.

A refactor that claims "no behaviour change" must leave this byte-identical.
The ratchet pins (detector, contract, LINE) only; this pins the full outputs:

- ``tealql detections --all --mode app --json`` and ``--mode logicsig`` (stdout + exit code)
- ``tealql brief --json`` (ABI surface, storage, itxns, group shape, attack surface, findings)
- ``lift_to_teal`` (the decompiled-and-recompiled TEAL, or the LiftError)
- ``compute_summaries`` of the lifter (per-sub result / effect dependencies)

over the distinct mainnet probes and ``tests/contracts``. Run it on the base
commit and on the refactor, then compare::

    nice -n 19 ionice -c3 uv run python tools/behavior_fingerprint.py run  --out base.jsonl
    nice -n 19 ionice -c3 uv run python tools/behavior_fingerprint.py run  --out new.jsonl
    uv run python tools/behavior_fingerprint.py diff base.jsonl new.jsonl

Each program runs in a fresh worker process (``--jobs``, default 2) so no cache
crosses programs. Run ``run`` twice on one tree first: the two files must agree,
or the fingerprint itself is not deterministic (``diff`` sorts frozenset reprs
in the summaries; any other run-to-run difference is a real nondeterminism bug).
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import multiprocessing as mp
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def programs() -> list[Path]:
    sys.path.insert(0, str(REPO))
    from tests.corpus_manifest import distinct_files
    probes = [p for _, p in distinct_files(REPO / "tests" / "mainnet-random-probes")]
    contracts = sorted((REPO / "tests" / "contracts").rglob("*.teal"))
    return probes + contracts


def _cli(argv: list[str]) -> dict:
    from tealql.cli.main import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as e:
            code = e.code
        except Exception as e:                       # a crash is an output too
            code = f"CRASH {type(e).__name__}: {e}"
    return {"code": code, "stdout": out.getvalue()}


def fingerprint(path: str) -> dict:
    rel = str(Path(path).relative_to(REPO))
    rec: dict = {"program": rel}
    rec["detections_app"] = _cli(["detections", path, "--all", "--mode", "app", "--json"])
    rec["detections_lsig"] = _cli(["detections", path, "--all", "--mode", "logicsig", "--json"])
    rec["brief"] = _cli(["brief", path, "--json"])
    try:
        from tealql.tealtools.lift.backend import lift_to_teal
        rec["lift"] = lift_to_teal(path)            # a PATH: source text is OSError'd as a filename
    except Exception as e:
        rec["lift"] = f"{type(e).__name__}: {e}"
    try:
        from tealql.tealtools.lift import build_lifter
        from tealql.tealtools.lift.summaries import compute_summaries
        from tealql.tealtools.ssa import SSAProgram
        lifter = build_lifter(SSAProgram(path))
        rec["summaries"] = None if lifter is None else {
            k: repr(v) for k, v in sorted(compute_summaries(lifter).items())}
    except Exception as e:
        rec["summaries"] = f"{type(e).__name__}: {e}"
    return rec


def _normalize(rec: dict) -> str:
    # Absolute paths differ between worktrees; everything else must not.
    return json.dumps(rec, sort_keys=True, default=str).replace(str(REPO) + "/", "")


def run(out: Path, jobs: int) -> None:
    paths = [str(p) for p in programs()]
    ctx = mp.get_context("spawn")
    with ctx.Pool(jobs, maxtasksperchild=1) as pool, out.open("w") as fh:
        for i, rec in enumerate(pool.imap(fingerprint, paths)):
            fh.write(_normalize(rec) + "\n")
            if i % 25 == 0:
                print(f"{i + 1}/{len(paths)}", file=sys.stderr, flush=True)


_SET = "frozenset({"


def _scan(s: str, i: int, stop: str) -> int:
    """Index of the first ``stop`` char at bracket depth 0 from ``i`` (quotes skipped)."""
    depth, quote = 0, None
    while i < len(s):
        c = s[i]
        if quote:
            quote = None if c == quote and s[i - 1] != "\\" else quote
        elif c in "'\"":
            quote = c
        elif depth == 0 and c in stop:
            return i
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        i += 1
    return i


def canonical_sets(s: str) -> str:
    """``s`` with each ``frozenset({...})``'s elements sorted: a set's repr order
    follows the process's hash seed, which is no behaviour."""
    out, i = [], 0
    while (j := s.find(_SET, i)) != -1:
        end = _scan(s, j + len(_SET), "}")
        elems, k = [], j + len(_SET)
        while k < end:
            e = _scan(s, k, ",}")
            elems.append(canonical_sets(s[k:e].strip()))
            k = e + 1
        out += [s[i:j], _SET, ", ".join(sorted(elems)), "})"]
        i = end + 2
    return "".join(out) + s[i:]


def _comparable(key: str, value):
    if key == "summaries" and isinstance(value, dict):
        return {k: canonical_sets(v) for k, v in value.items()}
    return value


def diff(a: Path, b: Path) -> int:
    ra = {json.loads(line)["program"]: json.loads(line) for line in a.open()}
    rb = {json.loads(line)["program"]: json.loads(line) for line in b.open()}
    bad = 0
    for prog in sorted(set(ra) | set(rb)):
        if prog not in ra or prog not in rb:
            print(f"{prog}: only in {'new' if prog not in ra else 'base'}")
            bad += 1
            continue
        for key in sorted(set(ra[prog]) | set(rb[prog])):
            x, y = _comparable(key, ra[prog].get(key)), _comparable(key, rb[prog].get(key))
            if x != y:
                bad += 1
                xs, ys = json.dumps(x, sort_keys=True), json.dumps(y, sort_keys=True)
                i = next((k for k in range(min(len(xs), len(ys))) if xs[k] != ys[k]), min(len(xs), len(ys)))
                print(f"{prog} [{key}] differs at char {i}:\n  base: …{xs[max(0, i - 80):i + 120]}\n"
                      f"  new:  …{ys[max(0, i - 80):i + 120]}")
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()[:16]  # noqa: E731
    print(f"{len(ra)} programs; {bad} differing outputs (base {digest(a)}, new {digest(b)})")
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--jobs", type=int, default=2)
    d = sub.add_parser("diff")
    d.add_argument("base", type=Path)
    d.add_argument("new", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "run":
        run(args.out, args.jobs)
        return 0
    return diff(args.base, args.new)


if __name__ == "__main__":
    sys.exit(main())
