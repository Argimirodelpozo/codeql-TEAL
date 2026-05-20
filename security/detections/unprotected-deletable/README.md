# Unprotected Deletable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == DeleteApplication`, *and* (b) no dominating predicate constrains `txn Sender == Global.CreatorAddress` on that path. The "anyone can delete" combination: the app is deletable in principle (the `is-deletable` precondition) *and* the deletion isn't gated by a creator-only check.

This is the strictly stronger version of `is-deletable`: every `unprotected-deletable` finding implies an `is-deletable` finding, but not the other way around.

## How it works

Two conjoined per-exit checks:
1. Approval exit isn't guarded against `OnCompletion == 5` (the `is-deletable` test).
2. No dominating predicate ties `Sender` to `Global.CreatorAddress` (or `app.Creator` via `app_params_get`).

If both hold, the exit is reported. The Python port uses the same `PathPredicateAnalysis` machinery and the `common.senderCreatorGuardDominates` helper.

## Files

- `unprotectedDeletable.ql` — CodeQL implementation. Combines `approvalExitUnguardedForAction(onCompletionDeleteApplication)` and `not senderCreatorGuardDominates(approvalBB)`.
- `unprotected_deletable.py` — Python port using the same two checks.
- `unprotectedDeletable.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel pair), `vuln-dispatch-table.teal` / `fixed-dispatch-table.teal` (dispatch-table shapes — the "fixed" variant uses a `match` table that the conservative form doesn't recognise as a guard).
