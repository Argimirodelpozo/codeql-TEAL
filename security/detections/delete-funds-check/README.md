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

## Files

- `delete_funds_check.py` — Python port. Walks `prog.assignments` once for each of the two opcodes.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair).
