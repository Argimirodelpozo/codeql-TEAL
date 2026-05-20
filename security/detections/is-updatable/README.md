# Updatable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == UpdateApplication` (value 4). A reachable update path means the app's approval / clear-state programs can be replaced — every assumption downstream contracts make about the app's behaviour (auth, fees, asset handling) can be silently rewritten.

The *unguarded* version, mirroring `is-deletable`. Pair with `unprotected-updatable` (additionally requires no sender-creator guard) and `timelock-upgrade` (additionally requires a timestamp delay even when guarded).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 4 (UpdateApplication). Otherwise it's reported.

Same conservative shape as `is-deletable`: dispatch tables (`match` / `switch`) aren't recognised as guards.

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

Test fixtures — `vuln` / `fixed` `.teal` programs, their built
CodeQL DBs, and the expected detector output — live under
`tests/tealtools/sec_guide/is_updatable/`, one directory per case.
