# Deletable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == DeleteApplication` (value 5). A reachable delete path means anyone who can invoke the app might be able to delete it — losing global state, any locked funds, and the app's ability to honour outstanding obligations.

This detector is the *unguarded* version: it flags any reachable delete path regardless of who can take it. Pair it with `unprotected-deletable` (which additionally checks for the lack of a sender-creator guard) and `delete-funds-check` (which checks for a balance == min_balance guard).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 5 (DeleteApplication). Otherwise the exit is reported.

The QL form is deliberately conservative: dispatch via `match` / `switch` tables is not recognised as a guard (treated as if the exit were reachable from all OnCompletion values). The Python port preserves the same shape so its findings match the QL `.expected`.

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
