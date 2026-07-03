# Missing Lease Validation

**Severity:** medium · **Applies to:** logicsig

## What it looks for

A delegated LogicSig signs the *shape* of a transaction, not a specific instance. If it approves a spend without constraining `txn Lease`, the same signed transaction can be resubmitted (replayed) until the delegating key rotates — there is no other per-instance uniqueness. A non-zero `Lease` makes the `(Sender, Lease)` pair single-use within the lease window, which is the canonical fix.

## How it works

Advisory, scoped to LogicSigs. For each approval exit, the detector flags it when no path to it constrains `txn Lease` via a comparison whose result reaches enforcement. It reuses the same `approval_exit_protected_for_field` machinery as the RekeyTo / TypeEnum detectors (via the shared `_ApprovalExitProtectedDetector` base); "protected" here means "Lease is compared and the comparison gates approval", polarity-agnostic — both `Lease != ZeroAddress` and `Lease == <const>` count.

It is deliberately narrow to `logicsig` programs: a stateful application has other replay protection (its own global/local state), so a missing Lease check there is usually not a finding, and the gating keeps the false-positive rate down for the common app case. Like the other sec-guide ports it is intentionally conservative — a contract that enforces uniqueness by some means this heuristic doesn't model (e.g. an app state nonce) is out of scope by the logicsig gating, not a target.

## Examples

Vulnerable — the detector flags this (a delegated spend with no Lease constraint):

```teal
#pragma version 10
txn Amount
int 100
<=
assert
int 1
return
```

Safe — the detector stays quiet (`Lease` is pinned non-zero and enforced):

```teal
#pragma version 10
txn Lease
global ZeroAddress
!=
assert
int 1
return
```

## Files

- `lease_validation.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under `tests/tealtools/sec_guide/lease_validation/`, one directory per case; a `vuln` / `safe` precision-and-recall corpus lives under `tests/benchmark/lease-validation/`.
