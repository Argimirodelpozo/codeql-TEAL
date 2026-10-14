# Deletable Application

**Severity:** informational · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == DeleteApplication` (value 5). A reachable delete path means anyone who can invoke the app might be able to delete it — losing global state, any locked funds, and the app's ability to honour outstanding obligations.

This detector is the *unguarded* version: it flags any reachable delete path regardless of who can take it. Pair it with `unprotected-deletable` (which additionally checks for the lack of a sender-creator guard) and `delete-funds-check` (which checks for a balance == min_balance guard).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 5 (DeleteApplication). Otherwise the exit is reported.

The walk is per edge (a shared exit is guarded when every incoming edge excludes 5), and `switch` / `match` dispatch edges on OnCompletion are recognised as guards, as are ordered bounds (`OnCompletion <= OptIn`) and an app-creation path (`txn ApplicationID == 0`).

## How to fix

Accept only the OnCompletion values the app supports: assert a whitelist (`txn OnCompletion; int NoOp; ==; assert`, a `!=`, or an ordered bound such as `OnCompletion <= OptIn`), or route with `switch` / `match` / `OnCompletion == K; bnz` / an `||` of `OnCompletion == K` tests, so that no path with `OnCompletion == 5` reaches an approving exit. The check is per edge: a shared `approve:` label reached only from DeleteApplication-excluding arms is clean. A path proven to be app creation (`txn ApplicationID == 0`) is excluded too.

<!-- verify: is-deletable clean -->
```teal
#pragma version 10
// Accept only the OnCompletion values the app supports.
txn OnCompletion
int NoOp
==
assert
int 1
return
```

Vulnerable counterpart — the non-NoOp arm lets DeleteApplication into the shared exit:

<!-- verify: is-deletable finding -->
```teal
#pragma version 10
txn OnCompletion
int NoOp
==
bnz approve
// the non-NoOp arm admits DeleteApplication into the shared exit
txn OnCompletion
int DeleteApplication
==
assert
approve:
int 1
return
```

```python
assert Txn.on_completion == OnCompleteAction.NoOp  # ARC4Contract: leave "DeleteApplication" out of allow_actions
```

If the app is meant to be deletable (this detector reports a property; whether *anyone* can do it is `unprotected-deletable`), suppress with `// tealql-ignore: is-deletable` on the flagged exit line or the line above it, or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The A6 (shared `approve:` label reached from several OnCompletion-excluding arms) and A13 (`txn GroupIndex; gtxns OnCompletion`, relational OnCompletion bounds) classes in `docs/REVIEW_2026_10_10.md` are fixed. A guard spelled in any form other than those listed above reads as absent, so the exit is reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: DeleteApplication reaches an approving exit — nothing
// branches OnCompletion == 5 away from approval
txn OnCompletion
int 5
==
bnz delete_handler
int 1
return
delete_handler:
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: DeleteApplication is rejected
txn OnCompletion
int 5
==
bnz reject
int 1
return
reject:
int 0
return
```

## Files

- `is_deletable.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/is_deletable/`, one directory per case.
