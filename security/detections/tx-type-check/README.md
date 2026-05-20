# Missing Transaction Type Restriction

**Severity:** high · **Applies to:** logicsig (primarily), application

## What it looks for

A contract — especially a LogicSig — that doesn't restrict `txn TypeEnum` (or the deprecated `Type` string field). Without this check, a LogicSig designed to approve a single payment may also approve unrelated transaction types (asset transfers, application calls, key registration, asset config) — every transaction type carries its own field set, including `AssetCloseTo`, `CloseRemainderTo`, `RekeyTo`, that may now be exploitable.

## How it works

**Strict-dominance form** — same machinery as `asset-close-to`. A comparison against either `TypeEnum` or the legacy `Type` field must dominate every approval exit. The detector accepts *either* field as a valid restriction.

## Files

- `tx_type_check.py` — Python port. Custom detector that runs the `_FieldValidatedDetector` machinery for both fields and flags only when neither is dominator-checked.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal`, `vuln-subroutine-dispatch.teal` / `fixed-subroutine-dispatch.teal` (subroutine-encapsulated TypeEnum checks).
