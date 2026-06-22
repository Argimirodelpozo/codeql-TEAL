"""Random mainnet probe sweep that PERSISTS every contract it fetches.

Samples diverse mainnet apps, saves each approval program's disassembled TEAL to
``tests/mainnet-random-probes/app_<id>.teal`` (a growing regression corpus), then
lifts -> recompiles -> dryruns the lift against the contract's DEPLOYED bytecode
(not a reassembly of the disasm -- some valid contracts don't survive the strict
assembler round-trip; see :func:`compare.compare`). Reports faithful / divergent /
lift-fail per contract.

    python -m tests.behavioral_lift.sweep_probes [count]

Probes are kept (teal only) so a contract that surfaced a bug becomes a permanent
test case. Re-runs skip ids already on disk for the dryrun but never re-delete.
"""
from __future__ import annotations

import json
import signal
import sys
import urllib.request
from pathlib import Path

from . import compare as C
from tealtools.utils.chain import INDEXER, fetch_approval

PROBES = Path(__file__).resolve().parents[2] / "tests" / "mainnet-random-probes"
# diverse cursors across the whole id space (early -> newest); dense so a sweep
# pulls a broad, varied sample. The indexer paginates from each cursor, so more
# cursors => more distinct apps per run.
CURSORS = (
    "", "100000", "1000000", "10000000", "31000000", "60000000", "90000000",
    "120000000", "160000000", "250000000", "400000000", "550000000",
    "700000000", "850000000", "1050000000", "1300000000", "1600000000",
    "1900000000", "2200000000", "2500000000", "2800000000", "3100000000",
    "3300000000", "3450000000", "3500000000", "3550000000", "3600000000",
)


def sample(per_cursor: int = 8, pages: int = 1, skip: set | None = None) -> list:
    """App ids sampled from each cursor, INTERLEAVED round-robin across cursors so
    the result spans the whole id space evenly (a caller fetching a prefix gets a
    mix of old/new apps -> diverse AVM versions, not all the oldest first).
    ``pages`` follows the indexer's ``next-token`` that deep per cursor (so repeat
    sweeps reach genuinely new apps); ``skip`` drops ids already known."""
    skip = skip or set()
    seen: set = set()
    per: list = []                                # one id-list per cursor
    for after in CURSORS:
        token, lst = after, []
        for _ in range(pages):
            try:
                q = (f"{INDEXER}/v2/applications?limit={per_cursor}"
                     + (f"&next={token}" if token else ""))
                d = json.loads(urllib.request.urlopen(q, timeout=25).read())
            except Exception as e:  # pragma: no cover - network
                print(f"  cursor {after!r} err: {str(e)[:40]}", flush=True)
                break
            for a in d.get("applications", []):
                i = a["id"]
                if not a.get("deleted") and i not in seen and i not in skip:
                    seen.add(i)
                    lst.append(i)
            token = d.get("next-token")
            if not token:
                break
        per.append(lst)
    out = []                                      # round-robin merge
    for col in range(max((len(x) for x in per), default=0)):
        for lst in per:
            if col < len(lst):
                out.append(lst[col])
    return out


class _Timeout(Exception):
    pass


def _pragma_version(teal: str) -> str:
    first = teal.lstrip().splitlines()[0] if teal.strip() else ""
    return first.split("version")[-1].strip() if "version" in first else "?"


def _validate(az, clear, aid, teal, bc, tally: dict) -> None:
    """Lift -> recompile -> dryrun vs deployed bytecode; record into ``tally``
    (keys faithful/diverge/liftfail/compfail). The probe teal is already saved."""
    nl = teal.count("\n")
    try:
        lifted = C.lift_to_teal(str(PROBES / f"app_{aid}.teal"))
    except Exception as e:
        signal.alarm(0)
        tally["liftfail"] += 1
        print(f"LIFTFAIL {aid} ({nl}L): {type(e).__name__}: {str(e)[:60]}", flush=True)
        return
    try:
        lb = C._compile(az, lifted)
    except Exception as e:
        signal.alarm(0)
        tally["compfail"] += 1
        print(f"COMPFAIL {aid} ({nl}L): {str(e)[:60]}", flush=True)
        return
    inputs = [[]] + [[s] for s in C._selectors(lifted)] + [[b"\x01\x02\x03\x04"]]
    m = d = 0
    diffs = []
    for args in inputs:
        for oc in C._OCS:
            try:
                ao, do = C._dryrun(az, bc, clear, args, oc)
                al, dl = C._dryrun(az, lb, clear, args, oc)
            except Exception as e:
                diffs.append(f"dryerr {str(e)[:20]}")
                continue
            if ao != al or (ao and do != dl):
                d += 1
                diffs.append(f"oc={oc} a={len(args)} o={ao} l={al}")
            else:
                m += 1
    signal.alarm(0)
    if d:
        tally["diverge"] += 1
        print(f"DIVERGE {aid} ({nl}L) m={m} d={d} {diffs[:3]}", flush=True)
    else:
        tally["faithful"] += 1
        print(f"FAITHFUL {aid} (v{_pragma_version(teal)}, {nl}L) m={m}", flush=True)


def _run(az, clear, ids: list, tally: dict) -> None:
    for aid in ids:
        signal.alarm(220)
        try:
            teal, bc = fetch_approval(aid)
            (PROBES / f"app_{aid}.teal").write_text(teal)      # PERSIST the probe
            _validate(az, clear, aid, teal, bc, tally)
        except _Timeout:
            tally["skip"] += 1
            print(f"TIMEOUT {aid}", flush=True)
        except Exception as e:
            signal.alarm(0)
            tally["skip"] += 1
            print(f"SKIP {aid}: {type(e).__name__}: {str(e)[:45]}", flush=True)


def _corpus_versions() -> dict:
    from collections import Counter
    c = Counter()
    for p in PROBES.glob("app_*.teal"):
        try:
            c[_pragma_version(p.read_text())] += 1
        except Exception:
            pass
    return dict(c)


def main(argv) -> int:
    PROBES.mkdir(parents=True, exist_ok=True)
    az = C.algod_client()
    clear = C._compile(az, "#pragma version 10\nint 1")
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
    have = {int(p.stem.split("_")[1]) for p in PROBES.glob("app_*.teal")}
    tally = dict(faithful=0, diverge=0, liftfail=0, compfail=0, skip=0)

    if argv and argv[0] == "byver":
        # Fetch broadly, keeping a contract only while its AVM version is still
        # under `target`; balances the corpus across versions. `max_fetch` caps
        # disassembles spent hunting rare (old/newest) versions.
        target = int(argv[1]) if len(argv) > 1 else 8
        max_fetch = int(argv[2]) if len(argv) > 2 else 300
        per_ver = _corpus_versions()
        print(f"corpus versions: {dict(sorted(per_ver.items()))} ; target {target}/ver", flush=True)
        cand = sample(pages=12, skip=have)
        print(f"{len(cand)} candidate new ids; fetching to balance versions", flush=True)
        fetched = 0
        for aid in cand:
            if fetched >= max_fetch:
                break
            if all(per_ver.get(str(v), 0) >= target for v in range(2, 12)):
                break                       # every v2..v11 satisfied
            signal.alarm(220)
            try:
                teal, bc = fetch_approval(aid)
                fetched += 1
                ver = _pragma_version(teal)
                if per_ver.get(ver, 0) >= target:
                    signal.alarm(0)
                    continue                # this version already has enough
                (PROBES / f"app_{aid}.teal").write_text(teal)
                _validate(az, clear, aid, teal, bc, tally)
                per_ver[ver] = per_ver.get(ver, 0) + 1
            except _Timeout:
                tally["skip"] += 1
                print(f"TIMEOUT {aid}", flush=True)
            except Exception as e:
                signal.alarm(0)
                tally["skip"] += 1
                print(f"SKIP {aid}: {type(e).__name__}: {str(e)[:45]}", flush=True)
        print(f"\nfetched {fetched} ; final versions: {dict(sorted(_corpus_versions().items()))}",
              flush=True)
    else:
        count = int(argv[0]) if argv else 60
        pages, ids = 1, []
        while len(ids) < count and pages <= 12:
            ids = sample(pages=pages, skip=have)
            pages += 1
        ids = ids[:count]
        print(f"sampled {len(ids)} NEW ids ({len(have)} already in corpus) -> {PROBES}", flush=True)
        _run(az, clear, ids, tally)

    kept = len(list(PROBES.glob("*.teal")))
    print(f"\n=== faithful={tally['faithful']} diverge={tally['diverge']} "
          f"liftfail={tally['liftfail']} compfail={tally['compfail']} skip={tally['skip']} "
          f"| corpus now {kept} probes ===", flush=True)
    return 1 if tally["diverge"] else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    raise SystemExit(main(sys.argv[1:]))
