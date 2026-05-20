# Missing AssetCloseTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that processes asset transfers but never checks `txn AssetCloseTo`. The `AssetCloseTo` field, when non-zero, transfers *all* remaining units of the named asset from the spending account to the address it points at — so an unchecked contract lets an attacker drain an asset balance in a single transaction.

## How it works

**Strict-dominance form.** A single equality / inequality comparison against `AssetCloseTo` must dominate every approval exit. If any approving path reaches `return 1` without first passing through a dominating `AssetCloseTo` check, the contract is flagged.

This is intentionally conservative: contracts that validate the field per-OnCompletion branch but not in a single dominating predicate will be flagged. The per-exit path-aware form is `rekey-to`'s shape.

## Files

- `assetCloseTo.ql` — CodeQL implementation. Uses `txnFieldValidatedOnAllPaths` from `SecGuideCommon.qll`.
- `asset_close_to.py` — Python port over `SSAProgram`. Uses `_FieldValidatedDetector` from `tealtools.detections._field_validated`.
- `assetCloseTo.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel real-world pair), `vuln-multi-branch.teal` / `fixed-multi-branch.teal` (synthetic per-branch-only check that the strict-dominance form flags).
