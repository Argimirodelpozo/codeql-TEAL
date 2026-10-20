"""Full-window historical replay: EVERY block of a round window, every call to
the target apps judged deployed-vs-lifted.

``ttreplay stream`` evaluates a contiguous range of blocks, carrying the
chain's state forward (see ``ttreplay/stream.go``); this driver picks the
targets, lifts their programs, cuts the window into chunks and keeps the rows.

The window is anchored at a fixed END round and grows BACKWARDS: chunk ``i``
covers ``[end - (i+1)*chunk + 1, end - i*chunk]``. Asking for more days later
only adds older chunks, and a chunk resumes from its last completed block, so
a run can be stopped and extended at will::

    GOMAXPROCS=1 GOMEMLIMIT=1GiB nice -n 19 ionice -c3 \
        python -m tests.replay_harness.stream --out full --days 30 --top 100
    python -m tests.replay_harness.stream --out full --summarize

Targets: the ``--top`` apps by call count (inner calls included) in a sample
of the window's blocks, fixed in ``targets.json`` on the first run.

Verdict rows (``rows.jsonl``) are per (group, target app; ``orig_pcs`` holds
only the app's pcs first covered there): the statuses of ``timetravel.classify``, plus LIFT_PENDING (the app's program at that block
had no lift yet: it changed during the chunk, lifts happen between chunks) and
LIFT_FAIL. Each target app also gets the entry-mutant oracle self-test once,
on a block where it was judged (``selftest.json``). After each chunk, every
DIVERGES group gets the cost control (``timetravel.cost_control``, recorded in
``controls.jsonl``): explained by padding the cheaper side up to the other's
cost, it reads COST_ARTIFACT.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import random
import re
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
        self._cov: dict[int, set] | None = None

    def thin_coverage(self, rows: list[dict]) -> None:
        """Keep in each row's ``orig_pcs`` only the pcs not yet recorded for
        its app: the summary needs their union, and full per-row lists made
        rows.jsonl ~86% coverage (a GB per few days). Seeded once per process
        by streaming the file."""
        with self.lock:
            if self._cov is None:
                self._cov = defaultdict(set)
                for r in _read_rows(self.out):
                    self._cov[r["app"]].update(r.get("orig_pcs") or ())
            for r in rows:
                pcs = r.pop("orig_pcs", None) or ()
                new = set(pcs) - self._cov[r["app"]]
                if new:
                    self._cov[r["app"]] |= new
                    r["orig_pcs"] = sorted(new)

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
                run.thin_coverage(rows)
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
    for r in iter_rows(run.out):
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

_FAILING_APP = re.compile(r"Details: app=(\d+)")


def attribute(rows, by_group: dict[tuple, set] | None = None):
    """A group calling several target apps is judged once, and a divergence is
    recorded against each of them. When the failure names the app whose
    program failed (``Details: app=N``) and N is one of the group's targets,
    the others are CO_DIVERGED: their own lift is not what failed.
    ``by_group`` (the target apps of each (round, group)) is computed from
    ``rows`` when not given; it needs only the groups that diverged."""
    if by_group is None:
        rows = list(rows)
        by_group = defaultdict(set)
        for r in rows:
            by_group[(r["round"], r["group"])].add(r["app"])
    for r in rows:
        m = _FAILING_APP.search(r.get("detail") or "") if r["status"] == "DIVERGES" else None
        if m and int(m.group(1)) != r["app"] and int(m.group(1)) in by_group.get((r["round"], r["group"]), ()):
            r = {**r, "status": "CO_DIVERGED", "culprit": int(m.group(1))}
        yield r


def apply_controls(rows, controls: dict[tuple, dict]):
    """A DIVERGES row whose cost control reproduced it (``timetravel.cost_control``)
    is COST_ARTIFACT; the group's other DIVERGES targets are CO_DIVERGED with it."""
    culprit = {(k[0], k[1]): k[2] for k, c in controls.items() if c.get("reproduced")}
    for r in rows:
        k = (r["round"], r["group"])
        if r["status"] == "DIVERGES" and k in culprit:
            if culprit[k] == r["app"]:
                c = controls[(*k, r["app"])]
                r = {**r, "status": "COST_ARTIFACT",
                     "control": {f: c[f] for f in ("padded", "site", "pad", "extra") if f in c}}
            else:
                r = {**r, "status": "CO_DIVERGED", "culprit": culprit[k]}
        yield r


def load_controls(out: Path) -> dict[tuple, dict]:
    p = out / "controls.jsonl"
    rows = [json.loads(line) for line in p.open()] if p.exists() else []
    return {(c["round"], c["group"], c["app"]): c for c in rows}


def run_controls(run: Run) -> Counter:
    """Cost control for every DIVERGES (round, group) not yet controlled: the
    app the failure names first, then the group's other diverging targets,
    until one reproduces. Each try is recorded, so a rerun skips it (unless an
    older control version left it unexplained)."""
    done = load_controls(run.out)
    pending: dict[tuple, list[dict]] = defaultdict(list)
    for r in iter_rows(run.out):
        if r["status"] == "DIVERGES":
            pending[(r["round"], r["group"])].append(r)
    stats: Counter = Counter()
    for (rnd, grp), rows in sorted(pending.items()):
        named = _FAILING_APP.search(rows[0].get("detail") or "")
        rows.sort(key=lambda r: (not named or r["app"] != int(named.group(1)), r["app"]))
        for r in rows:
            prev = done.get((rnd, grp, r["app"]))      # an explained row is no longer DIVERGES
            if prev and prev.get("v", 1) >= tt.CONTROL_VERSION:
                continue
            c = {"round": rnd, "group": grp, "app": r["app"],
                 **tt.cost_control(r["app"], rnd, grp, r.get("detail") or "", run.out)}
            with run.lock, (run.out / "controls.jsonl").open("a") as fh:
                fh.write(json.dumps(c) + "\n")
            stats["reproduced" if c["reproduced"] else "not_reproduced"] += 1
            if c["reproduced"]:
                break
    return stats


def _read_rows(out: Path):
    p = out / "rows.jsonl"
    if p.exists():
        with p.open() as fh:
            for line in fh:
                yield json.loads(line)


def iter_rows(out: Path):
    """The verdict rows, controls and attribution applied, STREAMED: the file
    grows to gigabytes over a long run, and every reader only aggregates."""
    controls = load_controls(out)
    diverged = {(r["round"], r["group"]) for r in apply_controls(_read_rows(out), controls)
                if r["status"] == "DIVERGES"}
    by_group: dict[tuple, set] = defaultdict(set)
    if diverged:
        for r in _read_rows(out):
            if (r["round"], r["group"]) in diverged:
                by_group[(r["round"], r["group"])].add(r["app"])
    yield from attribute(apply_controls(_read_rows(out), controls), by_group)


def load_rows(out: Path) -> list[dict]:
    return list(iter_rows(out))


def summarize(run: Run) -> str:
    meta = run.json("meta.json", {})
    targets = run.json("targets.json", [])
    selftest = run.json("selftest.json", {})
    done_blocks = sum(run.done_upto(tuple(map(int, p.name.split("-")))) - int(p.name.split("-")[0]) + 1
                      for p in run.progress.iterdir())
    by_app: dict[int, Counter] = defaultdict(Counter)
    cov: dict[int, set] = defaultdict(set)
    rounds: dict[int, set] = defaultdict(set)
    bad: list[dict] = []
    seen_bad: set = set()
    for r in iter_rows(run.out):
        by_app[r["app"]][r["status"]] += 1
        cov[r["app"]].update(r.get("orig_pcs") or [])
        rounds[r["app"]].add(r["round"])
        if r["status"] in ("DIVERGES", "BUDGET", "VERSION_ARTIFACT", "COST_ARTIFACT") \
                and (r["app"], r["status"]) not in seen_bad:
            seen_bad.add((r["app"], r["status"]))
            bad.append(r)
    total = Counter()
    for c in by_app.values():
        total.update(c)
    n_rows = sum(total.values())
    lines = [
        "# Full-window historical replay",
        "",
        f"Window end round {meta.get('end')}; {done_blocks:,} blocks streamed "
        f"(every block, state carried forward). Targets: top {len(targets)} apps by calls. "
        f"{n_rows:,} judged (group, app) rows: "
        + ", ".join(f"{k} {v:,}" for k, v in total.most_common()) + ".",
        "",
        "DIVERGES counts only the app whose program failed when the error names it; the other target apps "
        "of that group are CO_DIVERGED. AFTER_DIVERGENCE rows follow a divergence in the same block "
        "(state no longer comparable) and are not verdicts. COST_ARTIFACT: the deployed program, padded with "
        "no-ops costing at most the lift's extra opcodes, diverges the same way (OpUp routers size their budget "
        "calls, and pay their fees, from `global OpcodeBudget`).",
        "",
        "| app | blocks | rows | FAITHFUL | DIVERGES | co-diverged / after | BUDGET / cost artifact | lift pending/fail | oracle miss | PCs hit | self-test |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for t in targets:
        a = t["app"]
        c = by_app.get(a, Counter())
        st = selftest.get(str(a))
        lines.append(
            f"| {a} | {len(rounds[a]):,} | {sum(c.values()):,} | {c['FAITHFUL']:,} | {c['DIVERGES']:,} | "
            f"{c['CO_DIVERGED']:,} / {c['AFTER_DIVERGENCE']:,} | {c['BUDGET']:,} / {c['COST_ARTIFACT']:,} | {c['LIFT_PENDING'] + c['LIFT_FAIL'] + c['LIFT_TIMEOUT'] + c['ASM_FAIL']:,} | "
            f"{c['REPLAY_MISS'] + c['REPLAY_ERROR']:,} | {len(cov[a]):,} | "
            f"{'—' if st is None else ('ok' if st['ok'] else 'BROKEN')} |")
    if bad:
        lines += ["", "## Non-faithful rows (first per app/status)", ""]
        for r in bad:
            ctl = r.get("control")
            lines.append(f"- **{r['status']}** app {r['app']} round {r['round']} group {r['group']}: "
                         f"`{(r.get('detail') or '')[:300]}`"
                         + (_control_note(ctl) if ctl else ""))
    return "\n".join(lines) + "\n"


def _control_note(ctl: dict) -> str:
    if ctl.get("padded", "deployed") == "deployed":
        return f" (deployed + {ctl['pad']} no-ops at {ctl['site']} reproduces it; lift {ctl['extra']:+d} opcodes)"
    return f" (lift + {ctl['pad']} no-ops at {ctl['site']} replays faithfully; lift {ctl['extra']:+d} opcodes)"


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--days", type=float, default=30, help="window length back from the end round")
    ap.add_argument("--end", type=int, help="window end round (fixed on the first run; default: node's last round)")
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--target-samples", type=int, default=600, help="blocks sampled to rank the targets")
    ap.add_argument("--chunk", type=int, default=20000, help="blocks per chunk (one cold start each)")
    # Defaults are deliberately gentle: the run takes days and shares the machine
    # (and a free public node). Run it as `GOMAXPROCS=1 GOMEMLIMIT=1GiB nice -n 19 ionice -c3 ...`.
    ap.add_argument("--jobs", type=int, default=1, help="chunks streamed concurrently")
    ap.add_argument("--prefetch", type=int, default=2, help="blocks warmed ahead per stream")
    ap.add_argument("--lift-jobs", type=int, default=1)
    ap.add_argument("--summarize", action="store_true")
    ap.add_argument("--controls", action="store_true", help="run the cost control on uncontrolled DIVERGES rows")
    args = ap.parse_args(argv)
    run = Run(Path(args.out))
    if args.summarize:
        text = summarize(run)
        (run.out / "SUMMARY.md").write_text(text)
        print(text)
        return 0
    if args.controls:
        print(dict(run_controls(run)))
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
            log("cost controls", dict(run_controls(run)))
            (run.out / "SUMMARY.md").write_text(summarize(run))
    self_tests(run, lifts)
    text = summarize(run)
    (run.out / "SUMMARY.md").write_text(text)
    print(text)
    return 1 if any(r["status"] == "DIVERGES" for r in iter_rows(run.out)) else 0


if __name__ == "__main__":
    sys.exit(main())
