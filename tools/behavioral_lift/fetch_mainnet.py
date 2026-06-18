"""Fetch real deployed mainnet apps, disassemble to TEAL, and build CodeQL DBs
-- a generalisation corpus of contracts the lift has never seen.

  python -m tools.behavioral_lift.fetch_mainnet <out-dir> [app_id ...]

With no ids, samples a diverse batch from the public mainnet indexer.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

MAINNET = "https://mainnet-api.algonode.cloud"
INDEXER = "https://mainnet-idx.algonode.cloud"
LOCAL = "http://localhost:4001"
REPO = Path(__file__).resolve().parents[2]


def _get(url, data=None, ctype=None, token=None):
    req = urllib.request.Request(url, data=data)
    if ctype:
        req.add_header("Content-Type", ctype)
    if token:
        req.add_header("X-Algo-API-Token", token)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def sample_app_ids(n=60):
    # known protocol apps: Tinyman v2, Folks, AlgoFi, Pact, + a few more
    ids = [1002541853, 971350278, 818179346, 605929989,
           971368268, 818176933, 354073718, 1284326447]
    ranges = ("", "1000000", "50000000", "100000000", "300000000", "600000000",
              "900000000", "1200000000", "1400000000", "1700000000", "2000000000", "2500000000")
    for after in ranges:
        try:
            q = f"{INDEXER}/v2/applications?limit=8" + (f"&next={after}" if after else "")
            d = json.loads(_get(q))
            ids += [a["id"] for a in d.get("applications", []) if not a.get("deleted")]
        except Exception:
            pass
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out[:n]


def fetch_approval(app_id):
    """``(teal_text, deployed_bytecode)`` for an app's approval program. The
    bytecode is the on-chain program; keep it so the behavioural compare can
    dryrun it DIRECTLY (some valid contracts don't survive a disassemble ->
    reassemble round-trip through the strict assembler -- see compare.compare)."""
    d = json.loads(_get(f"{MAINNET}/v2/applications/{app_id}"))
    bytecode = base64.b64decode(d["params"]["approval-program"])
    if not bytecode:
        raise ValueError("no approval program")
    resp = _get(f"{LOCAL}/v2/teal/disassemble", data=bytecode,
                ctype="application/x-binary", token="a" * 64)
    return json.loads(resp)["result"], bytecode   # algod returns {"result": "<teal>"}


def fetch_teal(app_id):
    return fetch_approval(app_id)[0]


def build_db(teal_dir: Path):
    db = teal_dir / "db"
    subprocess.run(["codeql", "database", "create", str(db), "--overwrite", "-l", "teal",
                    "-s", str(teal_dir), "--search-path", str(REPO / ".codeql-extractors")],
                   check=True, capture_output=True, timeout=180)


def main(argv):
    out = Path(argv[0]) if argv else Path("/tmp/mainnet_contracts")
    ids = [int(x) for x in argv[1:]] or sample_app_ids()
    out.mkdir(parents=True, exist_ok=True)
    ok = 0
    for app_id in ids:
        d = out / f"app_{app_id}"
        d.mkdir(exist_ok=True)
        teal_path = d / f"app_{app_id}.teal"
        try:
            teal, bytecode = fetch_approval(app_id)
            teal_path.write_text(teal)
            (d / f"app_{app_id}.bin").write_bytes(bytecode)   # deployed program
            build_db(d)
            ok += 1
            nlines = len(teal_path.read_text().splitlines())
            print(f"  fetched+db app_{app_id} ({nlines} lines)", flush=True)
        except Exception as e:
            print(f"  FAIL app_{app_id}: {type(e).__name__}: {str(e)[:50]}", flush=True)
    print(f"\n=== {ok}/{len(ids)} fetched + DB-built into {out} ===")


if __name__ == "__main__":
    main(sys.argv[1:])
