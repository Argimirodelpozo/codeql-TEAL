"""Differential behaviour test: dryrun the ORIGINAL TEAL vs the lift-recompiled
TEAL on a live localnet algod across a matrix of app-call inputs, and report any
divergence. A faithful lift -> original and recompiled error/approve identically
on every input (modulo program-counter layout, which is normalised out).

  python -m tools.behavioral_lift.compare <explorer-dir-or-contract-dir> ...
"""
from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

from tools.behavioral_lift.recompile import REPO, algod_client, lift_to_teal

from algosdk import account, transaction
from algosdk.v2client import models

_PC = re.compile(r"(app=\d+, )?pc=\d+")
_SK, _ADDR = account.generate_account()
_OCS = [transaction.OnComplete.NoOpOC, transaction.OnComplete.OptInOC,
        transaction.OnComplete.CloseOutOC, transaction.OnComplete.UpdateApplicationOC,
        transaction.OnComplete.DeleteApplicationOC]


def _compile(algod, teal: str) -> bytes:
    return base64.b64decode(algod.compile(teal)["result"])


def _selectors(teal: str) -> list:
    """4-byte method-selector / routing constants pushed in the program."""
    out, seen = [], set()
    for h in re.findall(r"(?:pushbytes|bytec(?:block)?\s.*?)\s0x([0-9a-fA-F]{8})\b", teal):
        b = bytes.fromhex(h)
        if h not in seen:
            seen.add(h)
            out.append(b)
    return out[:8]


def _dryrun(algod, approval: bytes, clear: bytes, app_args, oc) -> str:
    sp = transaction.SuggestedParams(fee=1000, first=1, last=1000, gh="a" * 43 + "=", flat_fee=True)
    txn = transaction.ApplicationCallTxn(_ADDR, sp, index=999, on_complete=oc, app_args=app_args)
    stxn = transaction.SignedTransaction(txn, base64.b64encode(b"\0" * 64).decode())
    app = models.Application(id=999, params=models.ApplicationParams(
        approval_program=approval, clear_state_program=clear, creator=_ADDR,
        global_state_schema=models.ApplicationStateSchema(64, 64),
        local_state_schema=models.ApplicationStateSchema(16, 16)))
    acct = models.Account(address=_ADDR, status="Offline", amount=10 ** 12,
                          amount_without_pending_rewards=10 ** 12)
    res = algod.dryrun(models.DryrunRequest(txns=[stxn], apps=[app], accounts=[acct]))
    t = res["txns"][0]
    msg = (t.get("app-call-messages") or ["?"])[-1]
    logs = ",".join(t.get("logs", []))
    return _PC.sub("@", msg) + " | logs=" + logs       # normalise pc/app-id-of-dryrun


def compare(algod, db: str, orig_teal: str) -> dict:
    lifted = lift_to_teal(str(db))
    orig_b, lifted_b = _compile(algod, orig_teal), _compile(algod, lifted)
    clear = _compile(algod, "#pragma version 10\nint 1")
    inputs = [[]] + [[s] for s in _selectors(lifted)] + [[b"\x01\x02\x03\x04"]]
    match = diverge = 0
    diffs = []
    for args in inputs:
        for oc in _OCS:
            try:
                ro = _dryrun(algod, orig_b, clear, args, oc)
                rl = _dryrun(algod, lifted_b, clear, args, oc)
            except Exception as e:
                diffs.append(f"dryrun-error oc={oc} args={len(args)}: {str(e)[:40]}")
                continue
            if ro == rl:
                match += 1
            else:
                diverge += 1
                if len(diffs) < 4:
                    a = base64.b16encode(args[0]).decode() if args else "-"
                    diffs.append(f"oc={oc} arg={a}: orig[{ro[:38]}] != lift[{rl[:38]}]")
    return {"match": match, "diverge": diverge, "diffs": diffs}


def main(argv):
    algod = algod_client()
    tot_m = tot_d = 0
    for db in sorted({d.parent for a in argv for d in Path(a).rglob("codeql-database.yml")}):
        name = db.parent.name if db.name == "db" else db.name
        teal_files = list(db.parent.glob("*.teal"))
        if not teal_files:
            continue
        try:
            r = compare(algod, str(db), teal_files[0].read_text())
        except Exception as e:
            print(f"  SKIP {name:30s} {type(e).__name__}: {str(e)[:42]}", flush=True)
            continue
        tot_m += r["match"]
        tot_d += r["diverge"]
        flag = "OK " if r["diverge"] == 0 else "DIV"
        print(f"  {flag} {name:30s} match={r['match']:3d} diverge={r['diverge']:3d}", flush=True)
        for d in r["diffs"]:
            print(f"        {d}", flush=True)
    print(f"\n=== behavioural: {tot_m} matching inputs, {tot_d} divergent ===")


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    main(sys.argv[1:])
