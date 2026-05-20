# Missing Asset ID Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that handles asset-transfer transactions (`TypeEnum == axfer` is reachable) but never checks `txn XferAsset` against a specific asset ID. Without this check, a vault or escrow contract built for a specific asset can be tricked into approving transfers of *any* asset — including spam or worthless tokens — sometimes locking real assets or unlocking unintended ones.

## How it works

**Anywhere-checked form** — a weaker requirement than strict-dominance: the program just has to compare `XferAsset` against *some* value *somewhere*, not necessarily dominating every approval exit. The detector also gates on the contract actually being able to reach the axfer-handling code (otherwise the check is moot).

## Files

- `asset_id_validation.py` — Python port. Walks `prog.assignments` for both a `TypeEnum == axfer` axfer-reachability check and a `XferAsset` comparison anywhere.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel real-world pair).
