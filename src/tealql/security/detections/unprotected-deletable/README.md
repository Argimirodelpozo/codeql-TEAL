# Unprotected Deletable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == DeleteApplication`, *and* (b) no dominating predicate constrains `txn Sender == Global.CreatorAddress` on that path. The "anyone can delete" combination: the app is deletable in principle (the `is-deletable` precondition) *and* the deletion isn't gated by a creator-only check.

This is the strictly stronger version of `is-deletable`: every `unprotected-deletable` finding implies an `is-deletable` finding, but not the other way around.

## How it works

Two conjoined per-exit checks:
1. Approval exit isn't guarded against `OnCompletion == 5` (the `is-deletable` test).
2. No dominating predicate ties `Sender` to `Global.CreatorAddress` (or `app.Creator` via `app_params_get`).

If both hold, the exit is reported. The implementation uses `PathPredicateAnalysis` and the sender/creator guards owned by `_action_guards.py`.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: DeleteApplication allowed without access control —
// any account can delete the application
txn OnCompletion
int 5
==
bnz delete_handler
int 1
return
delete_handler:
// No sender == creator check
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: DeleteApplication restricted to the creator
txn OnCompletion
int 5
==
bnz delete_handler
int 1
return
delete_handler:
txn Sender
global CreatorAddress
==
assert
int 1
return
```

## Files

- `unprotected_deletable.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/unprotected_deletable/`, one directory per case.
