# Missing Transaction Type Restriction

**Severity:** high · **Applies to:** logicsig (primarily), application

## What it looks for

A contract — especially a LogicSig — that doesn't restrict `txn TypeEnum` (or the deprecated `Type` string field). Without this check, a LogicSig designed to approve a single payment may also approve unrelated transaction types (asset transfers, application calls, key registration, asset config) — every transaction type carries its own field set, including `AssetCloseTo`, `CloseRemainderTo`, `RekeyTo`, that may now be exploitable.

## How it works

**Strict-dominance form** — same machinery as `asset-close-to`. A comparison against either `TypeEnum` or the legacy `Type` field must dominate every approval exit. The detector accepts *either* field as a valid restriction.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No transaction type check — any type accepted
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn RekeyTo
global ZeroAddress
==
&&
// Missing: txn TypeEnum == int pay (or expected type)
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Transaction type explicitly restricted to payment (type 1)
txn TypeEnum
int 1
==
txn Amount
int 1000000
<=
&&
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

- `tx_type_check.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/tx_type_check/`, one directory per case.
