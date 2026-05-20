# Updatable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == UpdateApplication` (value 4). A reachable update path means the app's approval / clear-state programs can be replaced — every assumption downstream contracts make about the app's behaviour (auth, fees, asset handling) can be silently rewritten.

The *unguarded* version, mirroring `is-deletable`. Pair with `unprotected-updatable` (additionally requires no sender-creator guard) and `timelock-upgrade` (additionally requires a timestamp delay even when guarded).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 4 (UpdateApplication). Otherwise it's reported.

Same conservative shape as `is-deletable`: dispatch tables (`match` / `switch`) aren't recognised as guards.

## Files

- `is_updatable.py` — Python port over `PathPredicateAnalysis(prog)`.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel real-world pair), `vuln-fallthrough.teal` (an OnCompletion check that falls through to the update path on equality, still flagged).
