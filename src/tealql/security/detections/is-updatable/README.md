# Updatable Application

**Severity:** informational · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == UpdateApplication` (value 4). A reachable update path means the app's approval / clear-state programs can be replaced — every assumption downstream contracts make about the app's behaviour (auth, fees, asset handling) can be silently rewritten.

The *unguarded* version, mirroring `is-deletable`. Pair with `unprotected-updatable` (additionally requires no sender-creator guard) and `timelock-upgrade` (additionally requires a timestamp delay even when guarded).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 4 (UpdateApplication). Otherwise it's reported.

Same shape as `is-deletable`: the walk is per edge, and `switch` / `match` dispatch edges on OnCompletion are recognised as guards.

## How to fix

Accept only the OnCompletion values the app supports: assert a whitelist (`txn OnCompletion; int NoOp; ==; assert`, a `!=`, or an ordered bound such as `OnCompletion <= OptIn`), or route with `switch` / `match` / `OnCompletion == K; bnz` / an `||` of `OnCompletion == K` tests, so that no path with `OnCompletion == 4` reaches an approving exit. The check is per edge: a shared `approve:` label reached only from UpdateApplication-excluding arms is clean. A path proven to be app creation (`txn ApplicationID == 0`) is excluded too.

<!-- verify: is-updatable clean -->
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

Vulnerable counterpart — the non-NoOp arm lets UpdateApplication into the shared exit:

<!-- verify: is-updatable finding -->
```teal
#pragma version 10
txn OnCompletion
int NoOp
==
bnz approve
// the non-NoOp arm admits UpdateApplication into the shared exit
txn OnCompletion
int UpdateApplication
==
assert
approve:
int 1
return
```

```python
assert Txn.on_completion == OnCompleteAction.NoOp  # ARC4Contract: leave "UpdateApplication" out of allow_actions
```

If the app is meant to be updatable (this detector reports a property; whether *anyone* can do it is `unprotected-updatable`), suppress with `// tealql-ignore: is-updatable` on the flagged exit line or the line above it, or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The A6 (shared `approve:` label reached from several OnCompletion-excluding arms) and A13 (`txn GroupIndex; gtxns OnCompletion`, relational OnCompletion bounds) classes in `docs/REVIEW_2026_10_10.md` are fixed. A guard spelled in any form other than those listed above reads as absent, so the exit is reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: UpdateApplication reaches an approving exit unguarded
txn OnCompletion
int 4
==
bnz update_handler
int 1
return
update_handler:
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: UpdateApplication is rejected
txn OnCompletion
int 4
==
bnz reject
int 1
return
reject:
int 0
return
```

## Files

- `is_updatable.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/is_updatable/`, one directory per case.
