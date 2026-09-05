"""Differential behaviour test: dryrun the ORIGINAL TEAL vs the lift-recompiled
TEAL on a live localnet algod across a matrix of app-call inputs, and report any
divergence. A faithful lift -> original and recompiled error/approve identically
on every input (modulo program-counter layout, which is normalised out).

  python -m tests.behavioral_lift.compare <explorer-dir-or-contract-dir> ...
"""
from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

from functools import cache

from .recompile import REPO, algod_client, lift_to_teal

from .observations import compare_cases, observe_dryrun, required_effects

_OCS = (0, 1, 2, 4, 5)
PROTOCOL = 'future'  # pinned go-algorand 5.0.0 image in localnet.yml
ROUND = 500
TIMESTAMP = 1_700_000_000


@cache
def _address():
    from algosdk import encoding
    return encoding.encode_address(bytes([1]) * 32)


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


def _dryrun(algod, approval: bytes, clear: bytes, app_args, oc):
    from algosdk import transaction
    from algosdk.v2client import models
    address = _address()
    sp = transaction.SuggestedParams(fee=1000, first=1, last=1000, gh="a" * 43 + "=", flat_fee=True)
    txn = transaction.ApplicationCallTxn(address, sp, index=999, on_complete=oc, app_args=app_args)
    stxn = transaction.SignedTransaction(txn, base64.b64encode(b"\0" * 64).decode())
    app = models.Application(id=999, params=models.ApplicationParams(
        approval_program=approval, clear_state_program=clear, creator=address,
        global_state_schema=models.ApplicationStateSchema(32, 32),
        local_state_schema=models.ApplicationStateSchema(8, 8)))
    acct = models.Account(address=address, status="Offline", amount=10 ** 12,
                          amount_without_pending_rewards=10 ** 12,
                          apps_local_state=[models.ApplicationLocalState(
                              id=999, schema=models.ApplicationStateSchema(8, 8))])
    res = algod.dryrun(models.DryrunRequest(txns=[stxn], apps=[app], accounts=[acct],
                      protocol_version=PROTOCOL, round=ROUND, latest_timestamp=TIMESTAMP))
    return observe_dryrun(res)


def compare_bytecode(algod, original, lifted, clear, inputs, required):
    def execute(case):
        args, oc = case
        return (_dryrun(algod, original, clear, args, oc),
                _dryrun(algod, lifted, clear, args, oc))
    return compare_cases(((args, oc) for args in inputs for oc in _OCS),
                         execute, required=required)


def compare(algod, contract: str, orig_teal: str, orig_bytecode: bytes | None = None) -> dict:
    """Differential dryrun of the lifted program against the original.

    The baseline is the original's *deployed* program. Pass ``orig_bytecode``
    (the on-chain approval program) to dryrun it DIRECTLY -- prefer this. Some
    legitimately-deployed contracts assemble a stack the AVM accepts at runtime
    but the modern assembler's static frame-height check REJECTS on reassembly
    (e.g. an unconsumed ``box_del`` flag left under a value at a join, so a path
    reaches a merge one slot deeper than its siblings -> "frame_bury above
    stack"). Reassembling ``orig_teal`` then raises and the contract can't be
    compared at all, even though BOTH the on-chain original and our lift are
    valid. Using the deployed bytecode sidesteps the round-trip entirely; we
    fall back to assembling ``orig_teal`` only when no bytecode is given."""
    lifted = lift_to_teal(str(contract))
    orig_b = orig_bytecode if orig_bytecode is not None else _compile(algod, orig_teal)
    lifted_b = _compile(algod, lifted)
    clear = _compile(algod, "#pragma version 10\nint 1")
    inputs = [[]] + [[s] for s in _selectors(lifted)] + [[b"\x01\x02\x03\x04"]]
    return compare_bytecode(algod, orig_b, lifted_b, clear, inputs,
                            required_effects(orig_teal, lifted))


def main(argv):
    algod = algod_client()
    tot_m = tot_mech = tot_d = tot_appr = faithful = inconclusive = 0
    for contract in sorted({d.parent for a in argv for d in Path(a).rglob("codeql-database.yml")}):
        name = contract.parent.name if contract.name == "contract" else contract.name
        teal_files = list(contract.parent.glob("*.teal"))
        if not teal_files:
            continue
        # Prefer the deployed bytecode (app_<id>.bin from fetch_mainnet) as the
        # baseline -- a contract whose disassembly won't reassemble (strict
        # frame-height check) is still comparable against its on-chain program.
        bin_files = list(contract.parent.glob("*.bin"))
        orig_bytecode = bin_files[0].read_bytes() if bin_files else None
        try:
            r = compare(algod, str(contract), teal_files[0].read_text(), orig_bytecode)
        except Exception as e:
            inconclusive += 1
            print(f"  INCONCLUSIVE {name:30s} {type(e).__name__}: {str(e)[:42]}", flush=True)
            continue
        tot_m += r["match"]
        tot_mech += r["mech"]
        tot_d += r["diverge"]
        tot_appr += r["approve"]
        # behaviourally faithful = no APPROVE/reject (outcome) divergence on any input
        flag = r["status"]
        faithful += flag == "FAITHFUL"
        inconclusive += flag == "INCONCLUSIVE"
        print(f"  {flag} {name:26s} same={r['match'] + r['mech']:3d} "
              f"(appr={r['approve']}, {r['mech']} fail-op)  diverge={r['diverge']}", flush=True)
        for d in r["diffs"]:
            print(f"        {d}", flush=True)
    print(f"\n=== behaviourally faithful: {faithful} contracts | "
          f"{tot_m + tot_mech} same-outcome inputs ({tot_appr} both-APPROVE, "
          f"{tot_mech} fail-opcode-only), {tot_d} divergences, {inconclusive} inconclusive ===")
    return 1 if tot_d else 2 if inconclusive or not faithful else 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main(sys.argv[1:]))
