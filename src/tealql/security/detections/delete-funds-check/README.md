# Delete Without Balance Check

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == DeleteApplication`, *and* (b) the program nowhere combines a `balance` opcode with a `min_balance` opcode. A delete that doesn't first check `balance(app_account) == min_balance(app_account)` is one that can lock funds permanently — assets sent to the application account after deletion are unrecoverable.

This is a *funds-safety* check, not an auth check. `unprotected-deletable` covers the auth side.

## How it works

Two conditions:
1. Approval exit reachable under `OnCompletion == 5` (the `is-deletable` test).
2. `hasBalanceMinBalanceCheck()` is false globally — defined as "the program contains both a `balance` opcode and a `min_balance` opcode."

The presence-pair check is a proxy: it doesn't verify the two opcode outputs are actually compared, only that both appear. This matches the original QL form deliberately; tightening to a real comparison check is a follow-up.

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
