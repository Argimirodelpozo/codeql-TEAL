# Missing CloseRemainderTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that processes ALGO payment transactions but never checks `txn CloseRemainderTo`. When `CloseRemainderTo` is non-zero, the AVM closes the sending account at the end of the transaction and sends the *entire ALGO balance* (minus the payment amount and fee) to the named address. An attacker can use this to fully drain the account.

## How it works

**Strict-dominance form** — same machinery as `asset-close-to`: a single comparison against `CloseRemainderTo` must dominate every approval exit. Per-branch-only checks aren't recognised; the strict-dominance form is deliberately over-conservative.

## Files

- `close_remainder_to.py` — Python port. Uses `_FieldValidatedDetector` from `tealtools.detections._field_validated`.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-loop-like.teal` / `vuln-split-paths.teal` (control-flow shapes that still need a dominating check), `fixed-callsub.teal` (proves a subroutine-encapsulated check still dominates).
