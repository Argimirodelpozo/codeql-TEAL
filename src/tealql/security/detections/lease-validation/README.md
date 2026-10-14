# Missing Lease Validation

**Severity:** medium · **Applies to:** logicsig

## What it looks for

A delegated LogicSig signs the *shape* of a transaction, not a specific instance. If it approves a spend without constraining `txn Lease`, the same signed transaction can be resubmitted (replayed) until the delegating key rotates — there is no other per-instance uniqueness. A non-zero `Lease` makes the `(Sender, Lease)` pair single-use within the lease window, which is the canonical fix.

## How it works

Advisory, scoped to LogicSigs. For each approval exit, the detector flags it when no path to it constrains `txn Lease` via a comparison whose result reaches enforcement. It reuses the same signed-transaction approval-exit machinery as the RekeyTo / TypeEnum detectors (via the shared `_ApprovalExitProtectedDetector` base); "protected" here means "Lease is compared and the comparison gates approval", polarity-agnostic — both `Lease != ZeroAddress` and `Lease == <const>` count.

It is deliberately narrow to `logicsig` programs: a stateful application has other replay protection (its own global/local state), so a missing Lease check there is usually not a finding, and the gating keeps the false-positive rate down for the common app case. Like the other sec-guide ports it is intentionally conservative — a contract that enforces uniqueness by some means this heuristic doesn't model (e.g. an app state nonce) is out of scope by the logicsig gating, not a target.

## How to fix

Compare the signed transaction's own `Lease` and enforce the result on every path to every approving exit — typically pin it to a constant baked into the signed program, together with a bounded `LastValid` window so the `(Sender, Lease)` pair is single-use. `txn Lease`, `txn GroupIndex; gtxns Lease`, and `gtxn N Lease` under a `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) pin count. Both `Lease == <const>` and `Lease != global ZeroAddress` are credited (polarity-agnostic). Not credited: a dropped comparison, a `||` whose other arm does not also constrain `Lease`, or a sibling's `gtxn N Lease` on an unpinned index.

<!-- verify: lease-validation clean -->
```teal
#pragma version 8
txn Lease
byte 0x0000000000000000000000000000000000000000000000000000000000000001
==
assert
txn LastValid
int 30000000
<=
return
```

<!-- verify: lease-validation finding -->
```teal
#pragma version 8
txn LastValid
int 30000000
<=
return
```

```python
assert Txn.lease == TemplateVar[Bytes]("LEASE")
```

If the delegation is intentionally replayable (e.g. a recurring-payment logicsig rate-limited by `FirstValid`/`LastValid` arithmetic), put `// tealql-ignore: lease-validation` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`; apps have state-based replay protection), but `tealql detections FILE --detector lease-validation` runs it regardless of mode. Use `--mode app` / `--mode auto` with `--all`.
- A logicsig that prevents replay by other means (e.g. a single-round `FirstValid == LastValid` window, or a contract-account escrow rather than a delegation) is still reported: only a `Lease` comparison is credited.

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

- `src/tealql/security/detections/lease-validation/lease_validation.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/lease-validation/`.
