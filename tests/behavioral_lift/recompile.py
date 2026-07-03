"""Lift real TEAL -> Puya IR -> recompile to TEAL, and (optionally) compare the
original vs recompiled program's BEHAVIOUR on a live Algorand localnet via
algod dryrun. A real-world generalisation test for lift: does the
lift reconstruct an equivalent program for contracts it has never seen?

  python -m tests.behavioral_lift.recompile <contract-dir> ...

Each arg is a contract dir (holds a .teal) or a dir of such.
"""
from __future__ import annotations

import base64
import logging
import sys
from pathlib import Path

logging.getLogger("puya").setLevel(logging.CRITICAL)

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

# The backend (lift -> destructure -> MIR -> TEAL) is now a SHIPPED module,
# tealql.tealtools.lift.backend, so a pip-installed user can recompile too. Re-export
# here so this harness (and compare.py) keep importing `lift_to_teal` /
# `_destructure_with_orphans` from `recompile` unchanged.
from tealql.tealtools.lift.backend import lift_to_teal, _destructure_with_orphans  # noqa: F401,E402


def algod_client():
    from algosdk.v2client import algod
    return algod.AlgodClient("a" * 64, "http://localhost:4001")


def _contract_dirs(args):
    """Yield each contract directory (a dir holding a ``.teal``) named on the
    command line — the arg itself if it contains ``.teal``, else every such dir
    beneath it."""
    for a in args:
        p = Path(a)
        if list(p.glob("*.teal")):
            yield p
        else:
            yield from sorted({t.parent for t in p.rglob("*.teal")})


def main(argv):
    algod = algod_client()
    ok = lift_fail = compile_fail = 0
    for contract in _contract_dirs(argv):
        name = contract.name
        try:
            teal = lift_to_teal(str(contract))
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
