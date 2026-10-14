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

## How to fix

On every path that can run DeleteApplication, pin `txn Sender` to an address the caller cannot choose and enforce it (`assert`, or branch to a rejection). Credited addresses: `global CreatorAddress`, `app_params_get AppCreator`, a constant address literal, and an admin address read from global state that only trusted paths write (credited under stated premises — the run reports an `authority-assumption` notification and `complete: false`). The guard may sit on the Delete branch even when the exit is shared, may be `Sender == A || Sender == B` with every leaf trusted, `Sender == Creator || OnCompletion != DeleteApplication`, a `!=`-then-reject, or a callee's verdict that THIS caller asserts. A comparison against a caller-supplied value (`txna ApplicationArgs N`) is not a check.

<!-- verify: unprotected-deletable clean -->
```teal
#pragma version 10
txn OnCompletion
int DeleteApplication
==
bz done
txn Sender
global CreatorAddress
==
assert
done:
int 1
return
```

Vulnerable counterpart:

<!-- verify: unprotected-deletable finding -->
```teal
#pragma version 10
txn OnCompletion
int DeleteApplication
==
bz done
// no sender check: any account can delete
done:
int 1
return
```

```python
assert Txn.sender == Global.creator_address
```

If anyone-can-delete is intended (e.g. governance enforced by a co-signed group transaction this detector does not model), suppress with `// tealql-ignore: unprotected-deletable` on the flagged exit line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The A8 (creator pin returned through a `retsub` phi), A9 (phi of two separately computed trusted pins) and A10 (`assert(Sender == Creator || OC != UpdateApplication)`) classes in `docs/REVIEW_2026_10_10.md` are fixed. Authorisation that does not pin `txn Sender` — a multisig/lsig co-signer or a sibling transaction in the group — is not modelled and reads as absent.

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
