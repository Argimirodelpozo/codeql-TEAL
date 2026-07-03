"""CLI: fetch deployed mainnet apps into a directory (a generalisation corpus of
contracts the lift has never seen).

  python -m tests.behavioral_lift.fetch_mainnet <out-dir> [app_id ...]

With no ids, samples a diverse batch from the public mainnet indexer. The chain
helpers themselves live in :mod:`tealql.tealtools._utils.chain`.
"""
from __future__ import annotations

import sys
from pathlib import Path

from tealql.tealtools._utils.chain import fetch_approval, sample_app_ids  # noqa: F401 (re-export)


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
            ok += 1
            nlines = len(teal_path.read_text().splitlines())
            print(f"  fetched app_{app_id} ({nlines} lines)", flush=True)
        except Exception as e:
            print(f"  FAIL app_{app_id}: {type(e).__name__}: {str(e)[:50]}", flush=True)
    print(f"\n=== {ok}/{len(ids)} fetched into {out} (lift from raw .teal) ===")


if __name__ == "__main__":
    main(sys.argv[1:])
