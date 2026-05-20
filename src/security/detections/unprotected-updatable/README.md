# Unprotected Updatable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == UpdateApplication`, *and* (b) no dominating predicate constrains `txn Sender == Global.CreatorAddress`. Anyone-can-update means the approval / clear-state programs can be silently swapped out by any caller — every behavioural assumption downstream is invalidated.

Strictly stronger than `is-updatable`.

## How it works

Conjoined per-exit:
1. Approval exit isn't guarded against `OnCompletion == 4` (the `is-updatable` test).
2. No dominating predicate ties `Sender` to `Global.CreatorAddress`.

The detector reports each exit where both hold. The Python port reuses `PathPredicateAnalysis` and `common.senderCreatorGuardDominates`.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: UpdateApplication allowed without access control
// Any account can replace the contract code
txn OnCompletion
int 4
==
bnz update_handler
int 1
return
update_handler:
// No sender == creator check
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: UpdateApplication restricted to creator only
txn OnCompletion
int 4
==
bnz update_handler
int 1
return
update_handler:
txn Sender
global CreatorAddress
==
assert
int 1
return
```

## Files

- `unprotected_updatable.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs, their built
CodeQL DBs, and the expected detector output — live under
`tests/tealtools/sec_guide/unprotected_updatable/`, one directory per case.
