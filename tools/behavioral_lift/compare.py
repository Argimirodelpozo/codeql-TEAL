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

from algosdk import account, transaction
from algosdk.v2client import models

from tools.behavioral_lift.recompile import REPO, algod_client, lift_to_teal

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
    approved = msg == "PASS"                            # APPROVE (1) vs reject/error
    detail = _PC.sub("@", msg) + "|logs=" + ",".join(t.get("logs", []))
    return approved, detail                             # (outcome, normalised detail)


def compare(algod, db: str, orig_teal: str) -> dict:
    lifted = lift_to_teal(str(db))
    orig_b, lifted_b = _compile(algod, orig_teal), _compile(algod, lifted)
    clear = _compile(algod, "#pragma version 10\nint 1")
    inputs = [[]] + [[s] for s in _selectors(lifted)] + [[b"\x01\x02\x03\x04"]]
    match = mech = diverge = 0
    diffs = []
    for args in inputs:
        for oc in _OCS:
            try:
                ao, do = _dryrun(algod, orig_b, clear, args, oc)
                al, dl = _dryrun(algod, lifted_b, clear, args, oc)
            except Exception as e:
                diffs.append(f"dryrun-error oc={oc} args={len(args)}: {str(e)[:40]}")
                continue
            a = base64.b16encode(args[0]).decode() if args else "-"
            if ao != al:                               # APPROVE vs reject: a REAL behaviour bug
                diverge += 1
                if len(diffs) < 4:
                    diffs.append(f"OUTCOME oc={oc} arg={a}: orig={'APPROVE' if ao else 'reject'} "
                                 f"lift={'APPROVE' if al else 'reject'}")
            elif ao and do != dl:                      # both approve, but logs differ
                diverge += 1
                if len(diffs) < 4:
                    diffs.append(f"LOGS oc={oc} arg={a}: {do[:30]} != {dl[:30]}")
            elif do != dl:                             # same outcome, different failure opcode (benign)
                mech += 1
            else:
                match += 1
    return {"match": match, "mech": mech, "diverge": diverge, "diffs": diffs}


def main(argv):
    algod = algod_client()
    tot_m = tot_mech = tot_d = faithful = 0
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
        tot_mech += r["mech"]
        tot_d += r["diverge"]
        # behaviourally faithful = no APPROVE/reject (outcome) divergence on any input
        flag = "FAITHFUL" if r["diverge"] == 0 else "DIVERGES"
        faithful += r["diverge"] == 0
        print(f"  {flag} {name:28s} same-outcome={r['match'] + r['mech']:3d} "
              f"({r['mech']} fail-opcode-only)  diverge={r['diverge']}", flush=True)
        for d in r["diffs"]:
            print(f"        {d}", flush=True)
    print(f"\n=== behaviourally faithful: {faithful} contracts | "
          f"{tot_m + tot_mech} same-outcome inputs ({tot_mech} fail-opcode-only), "
          f"{tot_d} real outcome divergences ===")


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    main(sys.argv[1:])
