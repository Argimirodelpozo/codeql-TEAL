# Missing Fee Validation

**Severity:** high · **Applies to:** logicsig (primarily)

## What it looks for

A LogicSig that doesn't bound `txn Fee`. Without an upper bound on the fee, an attacker can submit transactions signed by the LogicSig with absurdly inflated fees (up to the account balance), draining the spending account through fee extraction rather than the payment amount.

## How it works

**Anywhere-checked form** — the program just has to compare `Fee` against *some* value *somewhere*. Path-aware variants (per-OnCompletion fee bounds) aren't required for the check to pass.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: txn Fee is never bounded — an attacker can set an
// enormous fee and drain the account
txn Amount
int 1000000
<=
// Missing: txn Fee <= global MinTxnFee
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: txn Fee bounded to the network minimum
txn Fee
global MinTxnFee
<=
txn Amount
int 1000000
<=
&&
assert
int 1
return
```

## Files

- `fee_validation.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/fee_validation/`, one directory per case.
