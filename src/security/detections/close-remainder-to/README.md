# Missing CloseRemainderTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that processes ALGO payment transactions but never checks `txn CloseRemainderTo`. When `CloseRemainderTo` is non-zero, the AVM closes the sending account at the end of the transaction and sends the *entire ALGO balance* (minus the payment amount and fee) to the named address. An attacker can use this to fully drain the account.

## How it works

**Strict-dominance form** — same machinery as `asset-close-to`: a single comparison against `CloseRemainderTo` must dominate every approval exit. Per-branch-only checks aren't recognised; the strict-dominance form is deliberately over-conservative.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No CloseRemainderTo check — all ALGO can be drained
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn CloseRemainderTo == global ZeroAddress
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: CloseRemainderTo validated against ZeroAddress
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn CloseRemainderTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `close_remainder_to.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/close_remainder_to/`, one directory per case.
