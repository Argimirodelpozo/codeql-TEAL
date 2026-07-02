"""Lift real TEAL -> Puya IR -> recompile to TEAL, and (optionally) compare the
original vs recompiled program's BEHAVIOUR on a live Algorand localnet via
algod dryrun. A real-world generalisation test for lift: does the
lift reconstruct an equivalent program for contracts it has never seen?

  python -m tests.behavioral_lift.recompile <db-or-dir> ...

Each arg is a CodeQL DB dir (has codeql-database.yml) or a dir of such.
"""
from __future__ import annotations

import base64
import logging
import sys
from pathlib import Path

logging.getLogger("puya").setLevel(logging.CRITICAL)

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src/analysis"))

# The backend (lift -> destructure -> MIR -> TEAL) is now a SHIPPED module,
# tealtools.lift.backend, so a pip-installed user can recompile too. Re-export
# here so this harness (and compare.py) keep importing `lift_to_teal` /
# `_destructure_with_orphans` from `recompile` unchanged.
from tealtools.lift.backend import lift_to_teal, _destructure_with_orphans  # noqa: F401,E402


def algod_client():
    from algosdk.v2client import algod
    return algod.AlgodClient("a" * 64, "http://localhost:4001")


def _dbs(args):
    for a in args:
        p = Path(a)
        if (p / "codeql-database.yml").exists():
            yield p
        else:
            yield from sorted(d.parent for d in p.rglob("codeql-database.yml"))


def main(argv):
    algod = algod_client()
    ok = lift_fail = compile_fail = 0
    for db in _dbs(argv):
        name = db.parent.name if db.name == "db" else db.name
        try:
            teal = lift_to_teal(str(db))
        except Exception as e:
            lift_fail += 1
            print(f"  LIFT-FAIL {name:34s} {type(e).__name__}: {str(e)[:45]}", flush=True)
            continue
        try:
            r = algod.compile(teal)
            nbytes = len(base64.b64decode(r["result"]))
            ok += 1
            print(f"  OK    {name:30s} {len(teal.splitlines()):4d} lines -> {nbytes}b", flush=True)
        except Exception as e:
            compile_fail += 1
            print(f"  ASM-FAIL  {name:34s} {str(e)[:50]}", flush=True)
    print(f"\n=== {ok} recompiled+assembled, {lift_fail} lift-fail, {compile_fail} asm-fail ===")


if __name__ == "__main__":
    main(sys.argv[1:])
