"""Behavioural gate for SSA-CONSTRUCTION changes.

A recorded project rule: any change to how the SSA is built (Braun phases,
depth caps, the lazy consumer-analyses, frame reconciliation, …) MUST be
behaviourally gated, not just snapshot-gated — the structural corpus test
(``test_lift_semantics``) checks IR shape, not runtime behaviour, and has
missed real divergences before.

This lifts each real contract + a sample of mainnet probes through the
current construction path, recompiles (``lift_to_teal``), and dryruns the
original vs the recompiled program on the live localnet, reporting any
outcome/log divergence. It is script-only (needs algod on
``http://localhost:4001``, token ``"a"*64``); pytest never collects it.

    python -m tests.behavioral_lift.ssa_construction_gate

Green = every contract that lifts is behaviourally faithful (``diverged=0``).
Skips are contracts that don't lift or have no fixture present — not failures.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .recompile import algod_client
from .compare import compare

REAL_DBS = [
    "tests/contracts/folks-consensus-v3",
    "tests/contracts/folks-consensus-v2",
    "tests/contracts/xgov",
    "tests/contracts/folks-xgov-registry",
]
N_PROBES = 8


def _teal_of(db_path: str) -> str:
    p = Path(db_path)
    if p.is_file():
        return p.read_text()
    tf = list(p.glob("*.teal"))
    return tf[0].read_text() if tf else ""


def main() -> int:
    algod = algod_client()
    probes = sorted(Path("tests/mainnet-random-probes").glob("*.teal"))[:N_PROBES]
    targets = [(d, d) for d in REAL_DBS] + [(str(p), str(p)) for p in probes]
    faithful = diverged = skipped = 0
    for name, db in targets:
        orig = _teal_of(db)
        if not orig:
            print(f"  SKIP {Path(name).name:34s} no teal"); skipped += 1; continue
        try:
            r = compare(algod, db, orig)
        except Exception as e:
            print(f"  SKIP {Path(name).name:34s} {type(e).__name__}: {str(e)[:44]}")
            skipped += 1
            continue
        d = r.get("diverge", 0)
        if d:
            diverged += 1
            print(f"  DIVERGE  {Path(name).name:32s} {r.get('diffs')}")
        else:
            faithful += 1
            print(f"  FAITHFUL {Path(name).name:32s} "
                  f"same={r.get('match', 0)} (appr={r.get('approve', 0)}) diverge=0")
    print(f"\n=== faithful={faithful}  diverged={diverged}  skipped={skipped} ===")
    return 1 if diverged else 0


if __name__ == "__main__":
    sys.exit(main())
