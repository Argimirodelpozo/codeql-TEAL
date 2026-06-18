"""Random mainnet probe sweep that PERSISTS every contract it fetches.

Samples diverse mainnet apps, saves each approval program's disassembled TEAL to
``tests/mainnet-random-probes/app_<id>.teal`` (a growing regression corpus), then
lifts -> recompiles -> dryruns the lift against the contract's DEPLOYED bytecode
(not a reassembly of the disasm -- some valid contracts don't survive the strict
assembler round-trip; see :func:`compare.compare`). Reports faithful / divergent /
lift-fail per contract.

    python -m tools.behavioral_lift.sweep_probes [count]

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
from .fetch_mainnet import INDEXER, fetch_approval

PROBES = Path(__file__).resolve().parents[2] / "tests" / "mainnet-random-probes"
# diverse cursors across the whole id space (early -> newest)
CURSORS = ("", "1000000", "20000000", "120000000", "400000000", "700000000",
           "1050000000", "1600000000", "2200000000", "2800000000", "3300000000")


def sample(per_cursor: int = 8) -> list:
    ids, seen = [], set()
    for after in CURSORS:
        try:
            q = f"{INDEXER}/v2/applications?limit={per_cursor}" + (f"&next={after}" if after else "")
            d = json.loads(urllib.request.urlopen(q, timeout=25).read())
            for a in d.get("applications", []):
                i = a["id"]
                if not a.get("deleted") and i not in seen:
                    seen.add(i)
                    ids.append(i)
        except Exception as e:  # pragma: no cover - network
            print(f"  cursor {after!r} err: {str(e)[:40]}", flush=True)
    return ids


class _Timeout(Exception):
    pass


def main(argv) -> int:
    PROBES.mkdir(parents=True, exist_ok=True)
    count = int(argv[0]) if argv else 60
    az = C.algod_client()
    clear = C._compile(az, "#pragma version 10\nint 1")
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))

    ids = sample()[:count]
    print(f"sampled {len(ids)} ids -> {PROBES}", flush=True)
    faith = div = liftfail = compfail = skip = 0
    for aid in ids:
        signal.alarm(220)
        try:
            teal, bc = fetch_approval(aid)
            (PROBES / f"app_{aid}.teal").write_text(teal)      # PERSIST the probe
            nl = teal.count("\n")
            try:
                lifted = C.lift_to_teal(str(PROBES / f"app_{aid}.teal"))
            except Exception as e:
                signal.alarm(0)
                liftfail += 1
                print(f"LIFTFAIL {aid} ({nl}L): {type(e).__name__}: {str(e)[:60]}", flush=True)
                continue
            try:
                lb = C._compile(az, lifted)
            except Exception as e:
                signal.alarm(0)
                compfail += 1
                print(f"COMPFAIL {aid} ({nl}L): {str(e)[:60]}", flush=True)
                continue
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
                div += 1
                print(f"DIVERGE {aid} ({nl}L) m={m} d={d} {diffs[:3]}", flush=True)
            else:
                faith += 1
                print(f"FAITHFUL {aid} ({nl}L) m={m}", flush=True)
        except _Timeout:
            skip += 1
            print(f"TIMEOUT {aid}", flush=True)
        except Exception as e:
            signal.alarm(0)
            skip += 1
            print(f"SKIP {aid}: {type(e).__name__}: {str(e)[:45]}", flush=True)
    kept = len(list(PROBES.glob("*.teal")))
    print(f"\n=== faithful={faith} diverge={div} liftfail={liftfail} "
          f"compfail={compfail} skip={skip} of {len(ids)} | corpus now {kept} probes ===",
          flush=True)
    return 1 if div else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    raise SystemExit(main(sys.argv[1:]))
