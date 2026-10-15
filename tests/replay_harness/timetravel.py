"""Historical-replay differential for the lift: does the lift-recompiled program
reproduce what the deployed program did on mainnet, on real inputs against the
real ledger state?

For each sampled block that calls an app, ``ttreplay`` (``ttreplay/``, built
inside a go-algorand checkout) re-evaluates the block with go-algorand's own
evaluator, reading state from a time-travel algod
(d13co/go-algorand@timetravel) at the round before the block, twice:

* ``orig``   — the program the app had at that round. Must reproduce the
  chain's ApplyData byte for byte; a group that does not is a REPLAY_MISS
  (an oracle problem, excluded from the verdict).
* ``lifted`` — the same program lifted -> Puya IR -> recompiled TEAL, swapped
  in for the app. Its ApplyData (logs, inner transactions, global/local state
  deltas) must equal the chain's, and its box writes must equal ``orig``'s.

Every group before the reported ones is evaluated too, so the reported groups
see exactly the state they saw on chain. Groups after the first non-faithful
group of a block are AFTER_DIVERGENCE (their state may already differ) and
are not counted.

  python -m tests.replay_harness.timetravel APP_ID [APP_ID ...] \
      [--samples N] [--seed S] [--out DIR] [--jobs J]

Environment: TEALQL_TT_NODE (default https://mainnet-api-dt.d13.co),
TEALQL_INDEXER (default https://mainnet-idx.algonode.cloud), TEALQL_TTREPLAY
(default ~/tools/go-algorand-timetravel/ttreplay).

Opt-in, network-bound and slow: not part of the hermetic suite. Results go to
``<out>/rows.jsonl`` (one row per replayed group) and ``<out>/SUMMARY.md``.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

NODE = os.environ.get("TEALQL_TT_NODE", "https://mainnet-api-dt.d13.co").rstrip("/")
INDEXER = os.environ.get("TEALQL_INDEXER", "https://mainnet-idx.algonode.cloud").rstrip("/")
TTREPLAY = os.environ.get("TEALQL_TTREPLAY", str(Path.home() / "tools/go-algorand-timetravel/ttreplay"))
REPO = Path(__file__).resolve().parents[2]
LIFT_TIMEOUT = int(os.environ.get("TEALQL_TT_LIFT_TIMEOUT", "900"))
REPLAY_TIMEOUT = int(os.environ.get("TEALQL_TT_REPLAY_TIMEOUT", "1800"))

# Lifted-program failures that are a cost artifact, not a behaviour change: the
# recompiled program may spend more opcode budget than the original did.
_BUDGET_MARKERS = ("dynamic cost budget exceeded", "cost budget exceeded")
# The lift emits AVM >= 10; an UpdateApplication installing an older-version
# program is then a "downgrade" the AVM refuses. ``replay_block`` re-runs such a
# block installing the LIFTED new program instead; a group still refused (the
# new program did not lift) is an oracle artifact, not counted.
_VERSION_ARTIFACT_MARKERS = ("program version downgrade",)


# ------------------------------------------------------------------ network

def _get_json(url: str, *, tries: int = 6):
    last = None
    for attempt in range(tries):
        if attempt:
            time.sleep(min(30, 0.5 * 2 ** attempt))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "tealql-timetravel"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
            if e.code < 500 and e.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
    raise RuntimeError(f"GET {url}: {last}")


def app_lifetime(app_id: int) -> tuple[int, int]:
    """(created round, last round to sample): deletion round or the node's tip."""
    info = _get_json(f"{INDEXER}/v2/applications/{app_id}?include-all=true")
    app = (info or {}).get("application") or {}
    created = app.get("created-at-round") or 1
    tip = _get_json(f"{NODE}/v2/status")["last-round"]
    end = app.get("deleted-at-round") or tip
    return created, min(end, tip)


def sample_rounds(app_id: int, n: int, seed: int) -> list[int]:
    """Up to ``n`` distinct blocks that call ``app_id`` (inner calls included),
    spread uniformly over its lifetime: random start rounds, each resolved to the
    next block with a matching transaction."""
    created, end = app_lifetime(app_id)
    rng = random.Random(f"{app_id}:{seed}")
    starts = sorted(rng.randrange(created, end) for _ in range(n * 2))
    found: list[int] = []
    for start in starts:
        if len(found) >= n:
            break
        page = _get_json(f"{INDEXER}/v2/transactions?application-id={app_id}"
                         f"&min-round={start}&max-round={end}&limit=1")
        txns = (page or {}).get("transactions") or []
        if txns:
            rnd = txns[0]["confirmed-round"]
            if rnd not in found:
                found.append(rnd)
    return sorted(found)


def programs_at(app_id: int, rnd: int) -> tuple[str, str] | None:
    """(approval b64, clear b64) the app had at the END of ``rnd``."""
    info = _get_json(f"{NODE}/v2/applications/{app_id}?round={rnd}")
    if not info or "params" not in info:
        return None
    p = info["params"]
    return p["approval-program"], p["clear-state-program"]


# ------------------------------------------------------------------ ttreplay

def _ttreplay(cmd: str, stdin: str, *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([TTREPLAY, cmd], input=stdin, capture_output=True, text=True, timeout=timeout)


def disassemble(program_b64: str) -> str:
    proc = _ttreplay("disasm", program_b64)
    if proc.returncode:
        raise RuntimeError("disassemble: " + proc.stderr.strip())
    return proc.stdout


def assemble(teal: str) -> tuple[str | None, str | None]:
    proc = _ttreplay("asm", teal)
    out = json.loads(proc.stdout or "{}")
    return out.get("program"), out.get("error") or (proc.stderr.strip() or None)


def program_version(program_b64: str) -> int:
    """The AVM version a program's bytecode starts with (a uvarint)."""
    v = shift = 0
    for b in base64.b64decode(program_b64):
        v |= (b & 0x7F) << shift
        if b < 0x80:
            return v
        shift += 7
    raise ValueError("empty program")


def at_version(teal: str, version: int) -> str:
    """``teal`` with its ``#pragma version`` set to ``version``."""
    return re.sub(r"(?m)^#pragma version \d+", f"#pragma version {version}", teal, count=1)


def instruction_count(teal: str) -> int:
    """Instructions in a TEAL listing (one PC each): every line that is not
    blank, a comment, a label, or a ``#pragma``."""
    n = 0
    for line in teal.splitlines():
        s = line.split("//", 1)[0].strip()
        if not s or s.startswith("#") or (s.endswith(":") and " " not in s):
            continue
        n += 1
    return n


# ------------------------------------------------------------------ lift

def lift_program(program_b64: str, cache: Path) -> dict:
    """Lift + recompile + assemble one program, cached by content hash.

    Returns {"sha", "status": OK|LIFT_FAIL|LIFT_TIMEOUT|ASM_FAIL, "lifted": b64?,
    "error"?, "orig_instructions", "lifted_instructions"?}."""
    sha = hashlib.sha256(base64.b64decode(program_b64)).hexdigest()[:16]
    meta_path = cache / f"{sha}.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    cache.mkdir(parents=True, exist_ok=True)
    teal = disassemble(program_b64)
    src = cache / f"{sha}.teal"
    src.write_text(teal)
    out = cache / f"{sha}.lifted.teal"
    meta = {"sha": sha, "orig_instructions": instruction_count(teal)}
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "tests.replay_harness.timetravel", "--lift-one", str(src), str(out)],
            cwd=REPO, capture_output=True, text=True, timeout=LIFT_TIMEOUT)
        meta["lift_seconds"] = round(time.time() - t0, 1)
        if proc.returncode or not out.exists():
            meta.update(status="LIFT_FAIL", error=(proc.stderr.strip().splitlines() or ["?"])[-1][:500])
        else:
            lifted_teal = out.read_text()
            program, err = assemble(lifted_teal)
            if program is None:
                meta.update(status="ASM_FAIL", error=(err or "?")[:500])
            else:
                meta.update(status="OK", lifted=program,
                            lifted_instructions=instruction_count(lifted_teal))
    except subprocess.TimeoutExpired:
        meta.update(status="LIFT_TIMEOUT", lift_seconds=LIFT_TIMEOUT)
    meta_path.write_text(json.dumps(meta))
    return meta


def _lift_one(src: str, dst: str) -> int:
    import logging
    logging.disable(logging.CRITICAL)
    sys.path.insert(0, str(REPO / "src"))
    from tealql.tealtools.lift.backend import lift_to_teal
    Path(dst).write_text(lift_to_teal(src))
    return 0


# ------------------------------------------------------------------ compare

def first_diff(a, b, path="$"):
    """First JSON path where two decoded values differ (None when equal)."""
    if type(a) is not type(b):
        return f"{path}: {json.dumps(a)[:160]} != {json.dumps(b)[:160]}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k}: {'missing in lifted' if k not in a else 'missing on chain'}"
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    return None if a == b else f"{path}: {json.dumps(a)[:160]} != {json.dumps(b)[:160]}"


def classify(orig: dict, lifted: dict) -> list[dict]:
    """Per reported group: FAITHFUL / DIVERGES / BUDGET / REPLAY_MISS /
    AFTER_DIVERGENCE, with the first difference for the non-faithful ones."""
    rows = []
    lifted_groups = {g["group"]: g for g in lifted.get("groups") or []}
    diverged = False
    for og in orig.get("groups") or []:
        gi = og["group"]
        lg = lifted_groups.get(gi)
        row = {"group": gi}
        if not og["match_chain"]:
            bad = next((t for t in og["txns"] if not t["match_chain"]), None)
            row.update(status="REPLAY_MISS", detail=(og.get("error") or (bad and (
                bad.get("error") or first_diff(json.loads(bad.get("apply_json") or "null"),
                                               json.loads(bad.get("chain_json") or "null")))) or "")[:400])
        elif diverged:
            row["status"] = "AFTER_DIVERGENCE"
        elif lg is None:
            row.update(status="DIVERGES", detail="lifted variant did not report this group: "
                       + (lifted.get("error") or "")[:300])
            diverged = True
        elif lg["match_chain"] and lg["box_writes"] == og["box_writes"]:
            row["status"] = "FAITHFUL"
        else:
            err = lg.get("error") or next((t.get("error") for t in lg["txns"] if t.get("error")), "")
            if err and any(m in err for m in _BUDGET_MARKERS):
                row.update(status="BUDGET", detail=err[:400])
            elif err and any(m in err for m in _VERSION_ARTIFACT_MARKERS):
                row.update(status="VERSION_ARTIFACT", detail=err[:400])
            else:
                if err:
                    detail = err
                elif not lg["match_chain"]:
                    bad = next(t for t in lg["txns"] if not t["match_chain"])
                    detail = f"txn {bad['index']}: " + (first_diff(
                        json.loads(bad.get("apply_json") or "null"),
                        json.loads(bad.get("chain_json") or "null")) or "?")
                else:
                    detail = "box writes: " + (first_diff(lg["box_writes"], og["box_writes"]) or "?")
                row.update(status="DIVERGES", detail=detail[:600])
            # The chain committed this group; the lifted run did not commit the
            # same thing (a failed group commits nothing at all), so every later
            # group of the block sees different state.
            diverged = True
        rows.append(row)
    return rows


# ------------------------------------------------------------------ driver

_VERSION_CAP = "greater than protocol supported version"
EXTRA_BUDGET = 320_000      # simulate's MaxExtraOpcodeBudget
_CURRENT_PROTOCOL: list[str] = []


def current_protocol() -> str:
    """Mainnet's consensus version now (the node's ``last-version``)."""
    if not _CURRENT_PROTOCOL:
        _CURRENT_PROTOCOL.append(_get_json(f"{NODE}/v2/status")["last-version"])
    return _CURRENT_PROTOCOL[0]


def _run_replay(req: dict) -> dict:
    proc = subprocess.run([TTREPLAY, "replay"], input=json.dumps(req), capture_output=True,
                          text=True, timeout=REPLAY_TIMEOUT)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"ttreplay exit {proc.returncode}: {proc.stderr.strip()[-400:]}"}


def install_map(app_id: int, rnd: int, lift: dict, lifts: Path) -> tuple[dict, str | None]:
    """``{sha256 hex of a program the block installs: replacement b64}`` for the
    lifted variants: the LIFTED new approval, and the new clear program at the
    same AVM version (approval and clear must match from v6). Both are raised
    to at least the overridden program's version, so the update is no
    downgrade. Returns ({}, why) when the new program has no lift."""
    progs = programs_at(app_id, rnd)
    if progs is None:
        return {}, "app has no programs after the block"
    new = lift_program(progs[0], lifts)
    if new.get("status") != "OK":
        return {}, f"installed program {new['sha']}: {new.get('status')} {new.get('error', '')}"[:300]
    version = max(program_version(new["lifted"]), program_version(lift["lifted"]))
    approval = new["lifted"]
    if program_version(approval) != version:
        approval, err = assemble(at_version((lifts / f"{new['sha']}.lifted.teal").read_text(), version))
        if approval is None:
            return {}, f"installed program at v{version}: {err}"
    clear, err = assemble(at_version(disassemble(progs[1]), version))
    if clear is None:
        return {}, f"installed clear program at v{version}: {err}"
    sha = lambda b: hashlib.sha256(base64.b64decode(b)).hexdigest()  # noqa: E731
    return {sha(progs[0]): approval, sha(progs[1]): clear}, None


def _refused(resp: dict, markers) -> bool:
    return any(m in (g.get("error") or "")
               for v in resp.get("variants") or [] if v.get("name", "").startswith("lifted")
               for g in v.get("groups") or [] for m in markers)


def replay_block(app_id: int, rnd: int, lift: dict, cache_dir: Path, lifts: Path | None = None) -> dict:
    """Replay under the block's own protocol. The lift emits AVM >= 10, which
    older blocks' protocols reject outright; then BOTH variants are re-run under
    mainnet's current protocol (``protocol_upgraded``), and the unmodified
    program's chain comparison says whether the upgrade changed its behaviour.

    An update the lifted variants refuse as a version downgrade is re-run with
    ``install_map``'s replacements installed instead (``installs_lifted``)."""
    variants = [{"name": "orig"}]
    if lift.get("status") == "OK":
        variants.append({"name": "lifted", "overrides": {str(app_id): {"approval": lift["lifted"]}}})
    req = {"node": NODE, "round": rnd, "apps": [app_id], "prefix": True, "coverage": True,
           "variants": variants, "cache_dir": str(cache_dir)}
    resp = _run_replay(req)
    if _refused(resp, (_VERSION_CAP,)):
        req["protocol"] = current_protocol()
        resp = {**_run_replay(req), "protocol_upgraded": True}
    if lifts is not None and _refused(resp, _VERSION_ARTIFACT_MARKERS):
        installs, why = install_map(app_id, rnd, lift, lifts)
        if why:
            resp["install_error"] = why
        else:
            for v in req["variants"]:
                if v["name"] != "orig":
                    v["installs"] = installs
            resp = {**_run_replay(req), "protocol_upgraded": resp.get("protocol_upgraded", False),
                    "installs_lifted": True}
    # Groups the recompiled program ran out of budget in are re-run with
    # simulate's maximum extra budget (judging behaviour where the lift costs
    # more) — only those groups: elsewhere the extra is itself an artifact,
    # OpUp callers read `global OpcodeBudget` and skip their padding calls.
    lifted = next((v for v in resp.get("variants") or [] if v.get("name") == "lifted"), None)
    short = [g["group"] for g in (lifted or {}).get("groups") or []
             if any(m in (g.get("error") or "") + "".join(t.get("error") or "" for t in g.get("txns") or [])
                    for m in _BUDGET_MARKERS)]
    if short:
        xb = {**next(v for v in req["variants"] if v["name"] == "lifted"), "name": "lifted_xb",
              "extra_budget": EXTRA_BUDGET, "extra_groups": short}
        again = _run_replay({**req, "variants": [{"name": "orig"}, xb]})
        resp["variants"] = list(resp["variants"]) + [v for v in again.get("variants") or []
                                                     if v.get("name") == "lifted_xb"]
    return resp


def _entry_mutant(lifted_teal: str) -> str:
    """The lifted program with an extra ``log`` before its first instruction:
    every execution's ApplyData changes, so the oracle MUST call it DIVERGES."""
    lines = lifted_teal.splitlines()
    k = next(i for i, ln in enumerate(lines) if ln.strip() and not ln.strip().startswith(
        ("#pragma", "intcblock", "bytecblock", "//")) and not ln.strip().endswith(":"))
    return "\n".join(lines[:k] + ["pushbytes 0x7465616c716c", "log"] + lines[k:]) + "\n"


INCONCLUSIVE = "inconclusive"


def oracle_self_test(app_id: int, rnd: int, lift: dict, out: Path) -> str | None:
    """Replay one block with the entry mutant; return an error unless every
    reported group of it is caught. Guards against an override that silently
    does not apply (every lifted run would then read FAITHFUL)."""
    teal = (out / "lifts" / f"{lift['sha']}.lifted.teal").read_text()
    program, err = assemble(_entry_mutant(teal))
    if program is None:
        return f"mutant did not assemble: {err}"
    resp = replay_block(app_id, rnd, {**lift, "lifted": program}, out / "httpcache", out / "lifts")
    variants = {v["name"]: v for v in resp.get("variants") or []}
    if "orig" not in variants or "lifted" not in variants:
        return f"mutant replay failed: {resp.get('error')}"
    rows = classify(variants["orig"], variants["lifted"])
    # BUDGET counts: the two extra opcodes can tip a budget-tight program over.
    caught = [r for r in rows if r["status"] in ("DIVERGES", "AFTER_DIVERGENCE", "BUDGET")]
    counted = [r for r in rows if r["status"] not in ("REPLAY_MISS", "VERSION_ARTIFACT")]
    if not counted:
        return INCONCLUSIVE           # nothing judgeable here: test on the next block
    if len(caught) != len(counted):
        return f"entry mutant NOT detected: {[(r['group'], r['status']) for r in rows]}"
    return None


def run_app(app_id: int, samples: int, seed: int, out: Path) -> list[dict]:
    log = lambda *a: print(f"[{app_id}]", *a, flush=True)  # noqa: E731
    rounds = sample_rounds(app_id, samples, seed)
    log(f"{len(rounds)} blocks sampled")
    rows = []
    self_tested = False
    for rnd in rounds:
        progs = programs_at(app_id, rnd - 1)
        base = {"app": app_id, "round": rnd}
        if progs is None:          # created in this very block
            rows.append({**base, "status": "SKIP", "detail": "app created in this block"})
            continue
        lift = lift_program(progs[0], out / "lifts")
        base["program"] = lift["sha"]
        t0 = time.time()
        resp = replay_block(app_id, rnd, lift, out / "httpcache", out / "lifts")
        variants = {v["name"]: v for v in resp.get("variants") or []}
        orig = variants.get("orig")
        if resp.get("error") or orig is None or orig.get("error"):
            rows.append({**base, "status": "REPLAY_ERROR",
                         "detail": (resp.get("error") or (orig or {}).get("error") or "?")[:400]})
            log(rnd, "REPLAY_ERROR", rows[-1]["detail"][:120])
            continue
        cov = sorted({pc for g in orig.get("groups") or [] for pc in (g.get("coverage") or {}).get(str(app_id), [])})
        if lift.get("status") != "OK":
            for g in orig.get("groups") or []:
                rows.append({**base, "group": g["group"], "status": lift["status"],
                             "detail": lift.get("error", ""), "orig_pcs": cov})
            log(rnd, lift["status"])
            continue
        if not self_tested:
            problem = oracle_self_test(app_id, rnd, lift, out)
            if problem and problem != INCONCLUSIVE:
                log("ORACLE BROKEN", problem)
                return rows + [{**base, "status": "ORACLE_BROKEN", "detail": problem[:400]}]
            self_tested = problem is None     # inconclusive: test again on the next block
        groups, lcov = judge(variants, app_id)
        lifted = variants.get("lifted") or {}
        for g in groups:
            rows.append({**base, **g, "orig_pcs": cov, "lifted_pcs": lcov,
                         "protocol_upgraded": bool(resp.get("protocol_upgraded")),
                         "installs_lifted": bool(resp.get("installs_lifted")),
                         "unsupported": sorted(set(orig.get("unsupported") or []) | set(lifted.get("unsupported") or []))})
        log(rnd, f"{time.time() - t0:.0f}s http={resp.get('http_calls')}",
            dict(Counter(g["status"] for g in groups)))
    return rows


def judge(variants: dict, app_id: int) -> tuple[list[dict], list[int]]:
    """Per-group verdicts for one block's ``orig`` / ``lifted`` (/ ``lifted_xb``)
    variants, with cost ratios, and the PCs of ``app_id`` the judged run covered.

    Judged on the plain lifted run. Only where it ran out of budget, on the
    extra-budget run instead (``over_budget`` marks those groups): programs that
    read ``global OpcodeBudget`` (OpUp loops) behave differently with more
    budget, so the extra must not be the default."""
    orig = variants["orig"]
    lifted = variants.get("lifted") or {"groups": [], "error": "missing lifted variant"}
    plain = {r["group"]: r["status"] for r in classify(orig, lifted)}
    judged = (variants.get("lifted_xb") or lifted) if "BUDGET" in plain.values() else lifted
    lcov = sorted({pc for g in judged.get("groups") or [] for pc in (g.get("coverage") or {}).get(str(app_id), [])})
    full = "lifted_xb" if "lifted_xb" in variants else "lifted"   # the run that completed
    ops = {name: {g["group"]: (g.get("ops") or {}).get(str(app_id), 0) for g in v.get("groups") or []}
           for name, v in variants.items()}
    cost = {name: {g["group"]: g.get("cost") or 0 for g in v.get("groups") or []}
            for name, v in variants.items()}
    groups = classify(orig, judged)
    for g in groups:
        g["over_budget"] = plain.get(g["group"]) == "BUDGET"
        o, lo = ops.get("orig", {}).get(g["group"]), ops.get(full, {}).get(g["group"])
        if o and lo:
            g["op_ratio"] = round(lo / o, 3)
        # Group-wide pooled budget: inner calls to OTHER apps cost the same in
        # both runs, so the difference is the lifted program's overhead.
        co, cl = cost.get("orig", {}).get(g["group"]), cost.get(full, {}).get(g["group"])
        if co and cl:
            g["cost_orig"], g["cost_lifted"] = co, cl
    return groups, lcov


def _restatus(r: dict) -> dict:
    """Re-derive the error-marker statuses from a row's recorded detail, so rows
    written by an older harness pick up later artifact rules."""
    if r["status"] == "DIVERGES":
        d = r.get("detail") or ""
        if any(m in d for m in _VERSION_ARTIFACT_MARKERS):
            return {**r, "status": "VERSION_ARTIFACT"}
        if any(m in d for m in _BUDGET_MARKERS):
            return {**r, "status": "BUDGET"}
    return r


def load_rows(out: Path) -> list[dict]:
    """Every row in ``out/rows.jsonl``; the latest run of an app replaces its
    earlier rows (an app's rows are appended together when it finishes)."""
    runs: dict = {}
    for line in (out / "rows.jsonl").read_text().splitlines():
        r = json.loads(line)
        runs.setdefault(r["app"], []).append(r)
    latest = []
    for rows in runs.values():
        # rows of one app run are contiguous; keep the last run's block
        last_start = max(i for i, r in enumerate(rows)
                         if i == 0 or r.get("_run") != rows[i - 1].get("_run"))
        latest += rows[last_start:]
    return latest


def summarize(rows: list[dict], lifts: Path) -> str:
    rows = [_restatus(r) for r in rows]
    by_app = defaultdict(list)
    for r in rows:
        by_app[r["app"]].append(r)
    out = ["# Historical-replay differential (time-travel)", "",
           f"Node `{NODE}`. One row per replayed group; FAITHFUL = lifted ApplyData and box "
           "writes equal the chain's. REPLAY_MISS = the deployed program itself did not "
           "reproduce the chain (oracle problem, not counted). The lift emits AVM >= 10; "
           "blocks whose protocol predates it are replayed (both variants) under mainnet's "
           "current protocol — `upgraded` counts those groups. Behaviour is judged on the "
           "plain lifted run; where that ran out of budget, on a re-run with "
           f"{EXTRA_BUDGET:,} extra opcode budget, and *over budget* counts those groups (the "
           "recompiled program could NOT have run within the budget the chain gave them). *op / cost ratio* is "
           "opcodes executed by the lifted program over the deployed one, and the group's pooled "
           "budget consumed with the lifted program over the deployed one.", "",
           "| app | blocks | groups | FAITHFUL | DIVERGES | BUDGET | over budget* | op / cost ratio (median) | lift fail | oracle miss/artifact | upgraded | programs | orig coverage |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for app, rs in sorted(by_app.items()):
        c = Counter(r["status"] for r in rs)
        progs = sorted({r.get("program") for r in rs if r.get("program")})
        cover = []
        for sha in progs:
            meta = json.loads((lifts / f"{sha}.json").read_text())
            pcs = {pc for r in rs if r.get("program") == sha for pc in r.get("orig_pcs") or []}
            total = meta.get("orig_instructions") or 1
            cover.append(f"{sha[:8]} {100 * len(pcs) / total:.0f}% ({meta['status']})")
        fails = c["LIFT_FAIL"] + c["LIFT_TIMEOUT"] + c["ASM_FAIL"]
        ratios = sorted(r["op_ratio"] for r in rs if r.get("op_ratio"))
        median = f"{ratios[len(ratios) // 2]:.2f}" if ratios else "-"
        costs = sorted(r["cost_lifted"] / r["cost_orig"] for r in rs if r.get("cost_orig"))
        cmed = f"{costs[len(costs) // 2]:.2f}" if costs else "-"
        out.append(f"| {app} | {len({r['round'] for r in rs})} | {len(rs)} | {c['FAITHFUL']} | "
                   f"{c['DIVERGES']} | {c['BUDGET']} | {sum(1 for r in rs if r.get('over_budget'))} | {median} / {cmed} | "
                   f"{fails} | {c['REPLAY_MISS'] + c['REPLAY_ERROR'] + c['VERSION_ARTIFACT']} | "
                   f"{sum(1 for r in rs if r.get('protocol_upgraded'))} | "
                   f"{len(progs)} | {'; '.join(cover)} |")
    bad = [r for r in rows if r["status"] in ("ORACLE_BROKEN", "DIVERGES", "BUDGET", "VERSION_ARTIFACT",
                                              "REPLAY_MISS", "REPLAY_ERROR",
                                              "LIFT_FAIL", "LIFT_TIMEOUT", "ASM_FAIL")]
    if bad:
        out += ["", "## Non-faithful rows (first per app/program/status)", ""]
        seen = set()
        for r in bad:
            key = (r["app"], r.get("program"), r["status"])
            if key in seen:
                continue
            seen.add(key)
            out.append(f"- **{r['status']}** app {r['app']} round {r['round']} group "
                       f"{r.get('group', '-')} program {r.get('program', '-')}: `{r.get('detail', '')}`")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["--lift-one"]:
        return _lift_one(argv[1], argv[2])
    if argv[:1] == ["--summarize"]:
        out = Path(argv[1])
        (out / "SUMMARY.md").write_text(summarize(load_rows(out), out / "lifts"))
        print((out / "SUMMARY.md").read_text())
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("apps", nargs="+", type=int)
    ap.add_argument("--samples", type=int, default=20, help="blocks per app (default 20)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="tt_results")
    ap.add_argument("--jobs", type=int, default=2, help="apps replayed concurrently (be polite)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not Path(TTREPLAY).exists():
        print(f"ttreplay not found at {TTREPLAY}; build it with tests/replay_harness/ttreplay/build.sh",
              file=sys.stderr)
        return 2
    rows: list[dict] = []
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        futures = {ex.submit(run_app, a, args.samples, args.seed, out): a for a in args.apps}
        for fut in cf.as_completed(futures):
            app = futures[fut]
            try:
                app_rows = fut.result()
            except Exception as e:     # one app's network failure must not lose the others
                app_rows = [{"app": app, "round": 0, "status": "REPLAY_ERROR", "detail": f"{type(e).__name__}: {e}"[:400]}]
            run_id = f"{os.getpid()}-{time.time_ns()}"
            app_rows = [{**r, "_run": run_id} for r in app_rows]
            rows += app_rows
            with (out / "rows.jsonl").open("a") as fh:
                for r in app_rows:
                    fh.write(json.dumps(r) + "\n")
    # Summarize every app in the directory (earlier invocations included).
    (out / "SUMMARY.md").write_text(summarize(load_rows(out), out / "lifts"))
    print((out / "SUMMARY.md").read_text())
    return 1 if any(r["status"] in ("DIVERGES", "ORACLE_BROKEN") for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
