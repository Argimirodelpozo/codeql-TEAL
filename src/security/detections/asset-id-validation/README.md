# Missing Asset ID Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that handles asset-transfer transactions (`TypeEnum == axfer` is reachable) but never checks `txn XferAsset` against a specific asset ID. Without this check, a vault or escrow contract built for a specific asset can be tricked into approving transfers of *any* asset — including spam or worthless tokens — sometimes locking real assets or unlocking unintended ones.

## How it works

**Anywhere-checked form** — a weaker requirement than strict-dominance: the program just has to compare `XferAsset` against *some* value *somewhere*, not necessarily dominating every approval exit. The detector also gates on the contract actually being able to reach the axfer-handling code (otherwise the check is moot).

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: handles an asset transfer (reads AssetAmount) but never
// checks XferAsset — the contract accepts ANY asset, not the intended one
txn AssetAmount
int 0
>
assert
// Missing: txn XferAsset == <expected ASA id>
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: XferAsset pinned to the expected ASA before approval
txn AssetAmount
int 0
>
txn XferAsset
int 31566704
==
&&
assert
int 1
return
```

## Files

- `asset_id_validation.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs, their built
CodeQL DBs, and the expected detector output — live under
`tests/tealtools/sec_guide/asset_id_validation/`, one directory per case.
