"""Full-window historical replay: EVERY block of a round window, every call to
the target apps judged deployed-vs-lifted.

``ttreplay stream`` evaluates a contiguous range of blocks, carrying the
chain's state forward (see ``ttreplay/stream.go``); this driver picks the
targets, lifts their programs, cuts the window into chunks and keeps the rows.

The window is anchored at a fixed END round and grows BACKWARDS: chunk ``i``
covers ``[end - (i+1)*chunk + 1, end - i*chunk]``. Asking for more days later
only adds older chunks, and a chunk resumes from its last completed block, so
a run can be stopped and extended at will::

    python -m tests.replay_harness.stream --out full --days 30 --top 100 --jobs 2
    python -m tests.replay_harness.stream --out full --summarize

Targets: the ``--top`` apps by call count (inner calls included) in a sample
of the window's blocks, fixed in ``targets.json`` on the first run.

Verdict rows (``rows.jsonl``) are per (group, target app): the statuses of
``timetravel.classify``, plus LIFT_PENDING (the app's program at that block
had no lift yet: it changed during the chunk, lifts happen between chunks) and
LIFT_FAIL. Each target app also gets the entry-mutant oracle self-test once,
on a block where it was judged (``selftest.json``).
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import random
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from tests.replay_harness import timetravel as tt

BLOCK_SECONDS = 2.8          # mainnet block time since 2024 (dynamic round times)


def _sha(program_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(program_b64)).hexdigest()


# ------------------------------------------------------------------ targets

def _block_apps(block: dict) -> Counter:
    """Calls per app in one block (JSON form), inner calls included."""
    calls: Counter = Counter()

    def walk(tx: dict) -> None:
        t = tx.get("txn", {})
        if t.get("type") == "appl":
            calls[t.get("apid", 0) or tx.get("apid", 0)] += 1
        for inner in (tx.get("dt") or {}).get("itx") or []:
            walk(inner)
    for tx in block.get("txns") or []:
        walk(tx)
    calls.pop(0, None)
    return calls


def top_apps(lo: int, hi: int, top: int, samples: int, seed: int = 0) -> list[dict]:
    """The ``top`` apps by calls in ``samples`` uniformly drawn blocks of [lo, hi]."""
    rounds = sorted(random.Random(seed).sample(range(lo, hi + 1), min(samples, hi - lo + 1)))
    total: Counter = Counter()
    with cf.ThreadPoolExecutor(4) as ex:
        for calls in ex.map(lambda r: _block_apps(tt._get_json(f"{tt.NODE}/v2/blocks/{r}?format=json")["block"]),
                            rounds):
            total.update(calls)
    return [{"app": a, "calls_per_block": round(c / len(rounds), 3)} for a, c in total.most_common(top)]


# ------------------------------------------------------------------ state

class Run:
    """The output directory: meta, targets, lifts, progress, rows."""

    def __init__(self, out: Path):
        self.out = out
        self.lifts = out / "lifts"
        self.progress = out / "progress"
        self.lock = threading.Lock()
        out.mkdir(parents=True, exist_ok=True)
        self.progress.mkdir(exist_ok=True)

    def json(self, name: str, default=None):
        p = self.out / name
        return json.loads(p.read_text()) if p.exists() else default

    def save(self, name: str, obj) -> None:
        tmp = self.out / (name + ".tmp")
        tmp.write_text(json.dumps(obj, indent=1))
        tmp.replace(self.out / name)

    def append_rows(self, rows: list[dict]) -> None:
        with self.lock, (self.out / "rows.jsonl").open("a") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def done_upto(self, chunk: tuple[int, int]) -> int:
        """Last completed round of a chunk (start - 1 when untouched)."""
        p = self.progress / f"{chunk[0]}-{chunk[1]}"
        return int(p.read_text()) if p.exists() else chunk[0] - 1

    def mark(self, chunk: tuple[int, int], rnd: int) -> None:
        (self.progress / f"{chunk[0]}-{chunk[1]}").write_text(str(rnd))


class Lifts:
    """Lifted programs by sha256 of the deployed approval program."""

    def __init__(self, run: Run):
        self.run = run
        self.lock = threading.Lock()
        self.by_sha: dict[str, dict] = {}        # sha256 -> lift_program meta
        for meta_path in run.lifts.glob("*.json") if run.lifts.exists() else []:
            meta = json.loads(meta_path.read_text())
            if "sha256" in meta:
                self.by_sha[meta["sha256"]] = meta

    def lift(self, program_b64: str) -> dict:
        sha = _sha(program_b64)
        with self.lock:
            if sha in self.by_sha:
                return self.by_sha[sha]
        meta = tt.lift_program(program_b64, self.run.lifts)
        if "sha256" not in meta:
            meta["sha256"] = sha
            (self.run.lifts / f"{meta['sha']}.json").write_text(json.dumps(meta))
        with self.lock:
            self.by_sha[sha] = meta
        return meta

    def swap_map(self) -> dict[str, str]:
        with self.lock:
            return {sha: m["lifted"] for sha, m in self.by_sha.items() if m.get("status") == "OK"}

    def status(self, program_b64: str) -> dict | None:
        with self.lock:
            return self.by_sha.get(_sha(program_b64))


# ------------------------------------------------------------------ rows

def block_rows(blk: dict, lifts: Lifts) -> list[dict]:
    """Rows for one streamed block: one per (judged group, target app)."""
    targets = blk.get("targets") or {}
    if not targets:
        return []
    variants = {v["name"]: v for v in blk.get("variants") or []}
    unlifted = blk.get("unlifted") or {}
    base = {"round": blk["round"], "protocol_upgraded": bool(blk.get("protocol_upgraded"))}
    if "orig" not in variants or variants["orig"].get("error"):
        detail = blk.get("error") or (variants.get("orig") or {}).get("error") or "no orig variant"
        return [{**base, "app": a, "group": int(g), "status": "REPLAY_ERROR", "detail": detail[:400]}
                for g, apps in targets.items() for a in apps]
    rows = []
    per_app: dict[int, tuple[dict, list[int]]] = {}
    for g, apps in targets.items():
        for a in apps:
            if a not in per_app:
                groups, lcov = tt.judge(variants, a)
                per_app[a] = ({r["group"]: r for r in groups}, lcov)
            verdicts, lcov = per_app[a]
            og = next((x for x in variants["orig"]["groups"] if x["group"] == int(g)), {})
            row = {**base, "app": a, "group": int(g),
                   "orig_pcs": (og.get("coverage") or {}).get(str(a), [])}
            prog = unlifted.get(str(a))
            if prog is not None:
                meta = lifts.status(prog)
                st = meta.get("status") if meta else None
                row.update(status="LIFT_PENDING" if st in (None, "OK") else st,
                           program=_sha(prog)[:16], detail=(meta or {}).get("error", "")[:300])
            else:
                row.update(verdicts.get(int(g), {"status": "DIVERGES", "detail": "group not judged"}))
            rows.append(row)
    return rows


# ------------------------------------------------------------------ chunks

def chunks(end: int, days: float, chunk: int) -> list[tuple[int, int]]:
    """Newest first: [end - (i+1)*chunk + 1, end - i*chunk] covering ``days``."""
    blocks = int(days * 86400 / BLOCK_SECONDS)
    out, hi = [], end
    while hi > end - blocks:
        lo = max(hi - chunk + 1, end - blocks + 1)
        out.append((lo, hi))
        hi = lo - 1
    return out


def stream_chunk(run: Run, lifts: Lifts, apps: list[int], chunk: tuple[int, int], prefetch: int) -> dict:
    start = run.done_upto(chunk) + 1
    stats: Counter = Counter()
    while start <= chunk[1]:
        req = {"node": tt.NODE, "start": start, "end": chunk[1], "apps": apps, "lifted": lifts.swap_map(),
               "extra_budget": tt.EXTRA_BUDGET, "coverage": True, "prefetch": prefetch}
        proc = subprocess.Popen([tt.TTREPLAY, "stream"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        proc.stdin.write(json.dumps(req))
        proc.stdin.close()
        last = start - 1
        new_programs: dict[str, str] = {}
        for line in proc.stdout:
            blk = json.loads(line)
            if blk.get("done"):
                stats["http"] += blk.get("http_calls", 0)
                break
            if blk.get("error") and not blk.get("targets") and not blk.get("chain_ok"):
                stats["chain_miss"] += 1
            stats["blocks"] += 1
            stats["rebased"] += bool(blk.get("rebased"))
            new_programs.update({p: p for p in (blk.get("unlifted") or {}).values()})
            rows = block_rows(blk, lifts)
            if rows:
                run.append_rows(rows)
                stats.update(r["status"] for r in rows)
            last = blk["round"]
            run.mark(chunk, last)
        proc.wait()
        # Lift what the chunk met; LIFT_PENDING rows stay (re-judge per block later).
        for prog in new_programs:
            lifts.lift(prog)
        if last < start:              # the process produced nothing: do not spin
            stats["stalled"] += 1
            break
        start = last + 1
    return dict(stats)


# ------------------------------------------------------------------ self-test

def self_tests(run: Run, lifts: Lifts) -> dict:
    """Entry-mutant self-test per target app, on a block where it was judged."""
    done = run.json("selftest.json", {})
    first: dict[int, int] = {}
    for r in load_rows(run.out):
        if r["status"] == "FAITHFUL" and str(r["app"]) not in done:
            first.setdefault(r["app"], r["round"])
    for app, rnd in sorted(first.items()):
        progs = tt.programs_at(app, rnd - 1)
        if progs is None:
            continue
        meta = lifts.lift(progs[0])
        if meta.get("status") != "OK":
            continue
        problem = tt.oracle_self_test(app, rnd, meta, run.out)
        if problem == tt.INCONCLUSIVE:
            continue
        done[str(app)] = {"round": rnd, "ok": problem is None, "detail": (problem or "")[:300]}
        run.save("selftest.json", done)
    return done


# ------------------------------------------------------------------ summary

def load_rows(out: Path) -> list[dict]:
    p = out / "rows.jsonl"
    return [json.loads(line) for line in p.open()] if p.exists() else []


def summarize(run: Run) -> str:
    rows = load_rows(run.out)
    meta = run.json("meta.json", {})
    targets = run.json("targets.json", [])
    selftest = run.json("selftest.json", {})
    done_blocks = sum(run.done_upto(tuple(map(int, p.name.split("-")))) - int(p.name.split("-")[0]) + 1
                      for p in run.progress.iterdir())
    by_app: dict[int, Counter] = defaultdict(Counter)
    cov: dict[int, set] = defaultdict(set)
    rounds: dict[int, set] = defaultdict(set)
    for r in rows:
        by_app[r["app"]][r["status"]] += 1
        cov[r["app"]].update(r.get("orig_pcs") or [])
        rounds[r["app"]].add(r["round"])
    total = Counter(r["status"] for r in rows)
    lines = [
        "# Full-window historical replay",
        "",
        f"Window end round {meta.get('end')}; {done_blocks:,} blocks streamed "
        f"(every block, state carried forward). Targets: top {len(targets)} apps by calls. "
        f"{len(rows):,} judged (group, app) rows: "
        + ", ".join(f"{k} {v:,}" for k, v in total.most_common()) + ".",
        "",
        "| app | blocks | rows | FAITHFUL | DIVERGES | BUDGET | lift pending/fail | oracle miss | PCs hit | self-test |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for t in targets:
        a = t["app"]
        c = by_app.get(a, Counter())
        st = selftest.get(str(a))
        lines.append(
            f"| {a} | {len(rounds[a]):,} | {sum(c.values()):,} | {c['FAITHFUL']:,} | {c['DIVERGES']:,} | "
            f"{c['BUDGET']:,} | {c['LIFT_PENDING'] + c['LIFT_FAIL'] + c['LIFT_TIMEOUT'] + c['ASM_FAIL']:,} | "
            f"{c['REPLAY_MISS'] + c['REPLAY_ERROR']:,} | {len(cov[a]):,} | "
            f"{'—' if st is None else ('ok' if st['ok'] else 'BROKEN')} |")
    bad = [r for r in rows if r["status"] in ("DIVERGES", "BUDGET", "VERSION_ARTIFACT")]
    if bad:
        lines += ["", "## Non-faithful rows (first per app/status)", ""]
        seen = set()
        for r in bad:
            k = (r["app"], r["status"])
            if k in seen:
                continue
            seen.add(k)
            lines.append(f"- **{r['status']}** app {r['app']} round {r['round']} group {r['group']}: "
                         f"`{(r.get('detail') or '')[:300]}`")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--days", type=float, default=30, help="window length back from the end round")
    ap.add_argument("--end", type=int, help="window end round (fixed on the first run; default: node's last round)")
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--target-samples", type=int, default=600, help="blocks sampled to rank the targets")
    ap.add_argument("--chunk", type=int, default=20000, help="blocks per chunk (one cold start each)")
    ap.add_argument("--jobs", type=int, default=2, help="chunks streamed concurrently (be polite)")
    ap.add_argument("--prefetch", type=int, default=8, help="blocks warmed ahead per stream")
    ap.add_argument("--lift-jobs", type=int, default=4)
    ap.add_argument("--summarize", action="store_true")
    args = ap.parse_args(argv)
    run = Run(Path(args.out))
    if args.summarize:
        text = summarize(run)
        (run.out / "SUMMARY.md").write_text(text)
        print(text)
        return 0
    if not Path(tt.TTREPLAY).exists():
        print(f"ttreplay not found at {tt.TTREPLAY}; build it with tests/replay_harness/ttreplay/build.sh",
              file=sys.stderr)
        return 2
    log = lambda *a: print(time.strftime("%H:%M:%S"), *a, flush=True)  # noqa: E731

    meta = run.json("meta.json")
    if meta is None:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tt.REPO, capture_output=True,
                                text=True).stdout.strip()
        # Lifts are cached by program, not by tealql version: the run validates THIS commit's lift.
        meta = {"end": args.end or tt._get_json(f"{tt.NODE}/v2/status")["last-round"], "node": tt.NODE,
                "tealql_commit": commit}
        run.save("meta.json", meta)
    end = meta["end"]
    plan = chunks(end, args.days, args.chunk)
    lo = plan[-1][0]

    targets = run.json("targets.json")
    if targets is None:
        log(f"ranking apps over [{lo}, {end}] from {args.target_samples} sampled blocks")
        targets = top_apps(lo, end, args.top, args.target_samples)
        run.save("targets.json", targets)
    apps = [t["app"] for t in targets]

    lifts = Lifts(run)
    log(f"lifting the {len(apps)} targets' programs at round {end}")
    with cf.ThreadPoolExecutor(args.lift_jobs) as ex:
        progs = list(ex.map(lambda a: tt.programs_at(a, end), apps))
        metas = list(ex.map(lambda p: lifts.lift(p[0]) if p else None, progs))
    log("lifts:", dict(Counter((m or {}).get("status", "NO_PROGRAM") for m in metas)))

    todo = [c for c in plan if run.done_upto(c) < c[1]]
    log(f"{len(plan)} chunks of {args.chunk} blocks ({args.days} days); {len(todo)} to stream")
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        futs = {ex.submit(stream_chunk, run, lifts, apps, c, args.prefetch): c for c in todo}
        for fut in cf.as_completed(futs):
            c = futs[fut]
            try:
                log("chunk", c, fut.result())
            except Exception as e:          # one chunk's failure must not lose the others
                log("chunk", c, "FAILED", f"{type(e).__name__}: {e}")
            (run.out / "SUMMARY.md").write_text(summarize(run))
    self_tests(run, lifts)
    text = summarize(run)
    (run.out / "SUMMARY.md").write_text(text)
    print(text)
    return 1 if any(r["status"] == "DIVERGES" for r in load_rows(run.out)) else 0


if __name__ == "__main__":
    sys.exit(main())
