# Delete Without Balance Check

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == DeleteApplication`, *and* (b) the program nowhere combines a `balance` opcode with a `min_balance` opcode. A delete that doesn't first check `balance(app_account) == min_balance(app_account)` is one that can lock funds permanently — assets sent to the application account after deletion are unrecoverable.

This is a *funds-safety* check, not an auth check. `unprotected-deletable` covers the auth side.

## How it works

Two conditions:
1. Approval exit reachable under `OnCompletion == 5` (the `is-deletable` test).
2. Some realizable entry path to the exit that can carry `OnCompletion == DeleteApplication` crosses no block that ENFORCES a comparison or subtraction tying a `balance` output to a `min_balance` output OF THE SAME ACCOUNT (one on each side), no inner `itxn_field CloseRemainderTo` (a close-out drains the ALGO, and fails while assets are still held), and no edge proving `balance(CurrentApplicationAddress) == 0`.

Opcode presence is not enough: two unrelated reads, a tie between two different accounts, or a tie whose result is popped, enforce nothing. The check is per exit — a funds check in another arm does not cover the Delete arm — and the walk carries a return stack, so a helper shared by two methods does not stitch one method's call site onto the other's continuation.

Out of scope: an app whose program has no `itxn_submit` (TEAL < 5 has none) can never move its own funds, so a Delete gated to the creator / a preserved admin strands nothing it could have spent. An OPEN delete of such an app is still reported (it may strand an escrow that requires this app's call).

## How to fix

Before approving a Delete, require that the app account holds nothing beyond its minimum balance: `balance` and `min_balance` values must meet in the SAME comparison or subtraction (`==`, `!=`, `<`, `<=`, `>`, `>=`, `-`, or their `b`-prefixed byte forms), one on each side, and the result must be enforced (`assert` or branch to a rejection) on every path to the Delete exit. Two unrelated reads, or a comparison whose result is popped, are not credited; a funds check in another arm does not cover the Delete arm.

<!-- verify: delete-funds-check clean -->
```teal
#pragma version 10
txn OnCompletion
int DeleteApplication
==
bnz delete
txn OnCompletion
int NoOp
==
assert
int 1
return
delete:
txn Sender
global CreatorAddress
==
assert
// every spendable microAlgo has been withdrawn first
global CurrentApplicationAddress
balance
global CurrentApplicationAddress
min_balance
==
assert
int 1
return
```

Vulnerable counterpart:

<!-- verify: delete-funds-check finding -->
```teal
#pragma version 10
txn OnCompletion
int DeleteApplication
==
bnz delete
txn OnCompletion
int NoOp
==
assert
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
delete:
txn Sender
global CreatorAddress
==
assert
int 1
return
```

```python
app = Global.current_application_address
assert app.balance == app.min_balance
```

Alternatively close the account out on the Delete path (an inner `pay` with `CloseRemainderTo`), which is credited. If a Delete with remaining funds is acceptable, suppress with `// tealql-ignore: delete-funds-check` on the flagged exit line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- **Callee-combined OnCompletion test.** An OC comparison ANDed through `callsub` helpers loses its predicate, so a NoOp-only exit can read as reachable with Delete (`oc-test-combined-in-callee`).
- **Shared Puya/Reach return tail.** A router whose methods all return through one `callsub; return` verdict can still be judged on a method arm whose verdict is 0.
- **Balance read through `acct_params_get`** (`AcctBalance` / `AcctMinBalance`) is not recognised as the balance pair.
- Fixed 2026-10-10 (field-measured): inner close-out before Delete, the `balance != 0` skip edge, the no-inner-txn app with a gated Delete, the different-accounts tie (an FN), and unrealizable paths through a shared helper.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: DeleteApplication allowed without checking if funds remain
txn OnCompletion
int 5
==
bnz delete_handler
int 1
return
delete_handler:
txn Sender
global CreatorAddress
==
assert
// (an app that pays out with inner transactions, so it can hold funds)
// Missing: balance == min_balance check
// Funds locked permanently if not drained first
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: DeleteApplication only allowed when balance == min_balance
txn OnCompletion
int 5
==
bnz delete_handler
int 1
return
delete_handler:
txn Sender
global CreatorAddress
==
assert
global CurrentApplicationAddress
balance
global CurrentApplicationAddress
min_balance
==
assert
int 1
return
```

## Files

- `delete_funds_check.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/delete_funds_check/`, one directory per case.
