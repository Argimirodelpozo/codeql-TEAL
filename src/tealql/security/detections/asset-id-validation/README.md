# Missing Asset ID Validation

**Severity:** high · **Applies to:** logicsig

## What it looks for

A contract that handles asset-transfer transactions (`TypeEnum == axfer` is reachable) but never checks `txn XferAsset` against a specific asset ID. Without this check, a vault or escrow contract built for a specific asset can be tricked into approving transfers of *any* asset — including spam or worthless tokens — sometimes locking real assets or unlocking unintended ones.

## How it works

**Per-exit form** — gated on the program reading any asset-transfer field (`txn` or `gtxn`); then every approving exit is reported unless every path from entry to it crosses a block that enforces (`assert` / branch-to-reject) a PIN of `txn XferAsset` or a sibling `gtxn N XferAsset` to a constant id (`==`, or a `!=` whose truth rejects).

## How to fix

Compare `txn XferAsset` (or the sibling's `gtxn N XferAsset`) against the
intended ASA id and enforce the result (`assert`, or a branch whose failing edge
rejects) on every path to every approving exit.

<!-- verify: asset-id-validation clean -->
```teal
#pragma version 8
// logicsig: approve only an axfer of the intended ASA
txn TypeEnum
int axfer
==
txn XferAsset
int 31566704
==
&&
txn AssetCloseTo
global ZeroAddress
==
&&
txn RekeyTo
global ZeroAddress
==
&&
assert
int 1
return
```

<!-- verify: asset-id-validation finding -->
```teal
#pragma version 8
// VULNERABLE: any asset is approved
txn TypeEnum
int axfer
==
txn AssetAmount
int 1000
<=
&&
assert
int 1
return
```

```python
assert Txn.xfer_asset == Asset(31566704)
```

Suppress an intended finding with `// tealql-ignore: asset-id-validation` on the
flagged exit line (or the line above), or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

- A pin on an arbitrary sibling `gtxn N XferAsset` still silences it (the
  transfer is usually a sibling, so sibling reads are seeded).
- Fixed 2026-10-10: `XferAsset != 0` and a comparison against an lsig `arg` no
  longer count — the pin must be to a constant id.

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

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/asset_id_validation/`, one directory per case.
