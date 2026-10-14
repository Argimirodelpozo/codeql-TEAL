# Unprotected Updatable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == UpdateApplication`, *and* (b) no dominating predicate constrains `txn Sender == Global.CreatorAddress`. Anyone-can-update means the approval / clear-state programs can be silently swapped out by any caller — every behavioural assumption downstream is invalidated.

Strictly stronger than `is-updatable`.

## How it works

Conjoined per-exit:
1. Approval exit isn't guarded against `OnCompletion == 4` (the `is-updatable` test).
2. No dominating predicate ties `Sender` to `Global.CreatorAddress`.

The detector reports each exit where both hold. It reuses `PathPredicateAnalysis` and the sender/creator guards owned by `_action_guards.py`.

## How to fix

On every path that can run UpdateApplication, pin `txn Sender` to an address the caller cannot choose and enforce it (`assert`, or branch to a rejection). Credited addresses: `global CreatorAddress`, `app_params_get AppCreator`, a constant address literal, and an admin address read from global state that only trusted paths write (credited under stated premises — the run reports an `authority-assumption` notification and `complete: false`). The guard may sit on the Update branch even when the exit is shared, may be `Sender == A || Sender == B` with every leaf trusted, `Sender == Creator || OnCompletion != UpdateApplication`, a `!=`-then-reject, or a callee's verdict that THIS caller asserts. A comparison against a caller-supplied value (`txna ApplicationArgs N`) is not a check.

<!-- verify: unprotected-updatable clean -->
```teal
#pragma version 10
txn OnCompletion
int UpdateApplication
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

<!-- verify: unprotected-updatable finding -->
```teal
#pragma version 10
txn OnCompletion
int UpdateApplication
==
bz done
// no sender check: any account can update
done:
int 1
return
```

```python
assert Txn.sender == Global.creator_address
```

If anyone-can-update is intended (e.g. governance enforced by a co-signed group transaction this detector does not model), suppress with `// tealql-ignore: unprotected-updatable` on the flagged exit line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The A8 (creator pin returned through a `retsub` phi), A9 (phi of two separately computed trusted pins) and A10 (`assert(Sender == Creator || OC != UpdateApplication)`) classes in `docs/REVIEW_2026_10_10.md` are fixed. Credited since 2026-10-10: a FIXED-position group member's sender (`gtxn K Sender`, e.g. under `GroupSize == 1 && GroupIndex == 0`, or a creator-signed sibling) pinned to a SIGNING PRINCIPAL (`global CreatorAddress`, `AppCreator`, or state captured from `txn Sender`) — the signature covers the group id; and `global CallerApplicationID == <non-zero const>`. A sibling pinned to a stored or constant address that may be a logicsig escrow (`gtxn 1 Sender == app_global_get "Escrow"`) is NOT credited (an escrow program signs for anyone). A foreign app's admin read through a subroutine parameter merged across call sites is still not credited.

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

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/unprotected_updatable/`, one directory per case.
