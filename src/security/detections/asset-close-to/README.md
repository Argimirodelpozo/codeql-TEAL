# Missing AssetCloseTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that processes asset transfers but never checks `txn AssetCloseTo`. The `AssetCloseTo` field, when non-zero, transfers *all* remaining units of the named asset from the spending account to the address it points at — so an unchecked contract lets an attacker drain an asset balance in a single transaction.

## How it works

**Strict-dominance form.** A single equality / inequality comparison against `AssetCloseTo` must dominate every approval exit. If any approving path reaches `return 1` without first passing through a dominating `AssetCloseTo` check, the contract is flagged.

This is intentionally conservative: contracts that validate the field per-OnCompletion branch but not in a single dominating predicate will be flagged. The per-exit path-aware form is `rekey-to`'s shape.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No AssetCloseTo check — every unit of the asset can be drained
txn AssetAmount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn AssetCloseTo == global ZeroAddress
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: AssetCloseTo validated against ZeroAddress
txn AssetAmount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn AssetCloseTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `asset_close_to.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs, their built
CodeQL DBs, and the expected detector output — live under
`tests/tealtools/sec_guide/asset_close_to/`, one directory per case.
