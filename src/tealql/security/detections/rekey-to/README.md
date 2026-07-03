# Missing RekeyTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract with at least one approval exit that doesn't validate `txn RekeyTo` against the zero address. When `RekeyTo` is set to a non-zero address, the AVM permanently rebinds the signing key of the spending account to that address — an attacker can effectively steal an escrow account, a delegated LogicSig, or a stateful contract's controllable address with one well-crafted transaction.

## How it works

**Per-exit path-aware form** — unlike the strict-dominance detections, this one flags *each* unprotected approval exit individually. An approval exit is "protected" when one of the dominating branch predicates (along every CFG path from entry to the exit) constrains `RekeyTo` to zero. A program with three approving paths, two of which check `RekeyTo` and one of which doesn't, produces one finding pointing at the unprotected path.

This shape lets the detector handle realistic dispatch tables that route different OnCompletion values down different branches, with `RekeyTo` checks only in the branches that actually need them.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No RekeyTo check — attacker can rekey account to themselves
txn Amount
int 500000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn RekeyTo == global ZeroAddress
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: RekeyTo validated against ZeroAddress
txn Amount
int 500000
<=
txn Fee
global MinTxnFee
<=
&&
txn RekeyTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `rekey_to.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/rekey_to/`, one directory per case.
