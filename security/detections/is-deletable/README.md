# Deletable Application

**Severity:** high · **Applies to:** application

## What it looks for

A stateful application with at least one approving path reachable under `OnCompletion == DeleteApplication` (value 5). A reachable delete path means anyone who can invoke the app might be able to delete it — losing global state, any locked funds, and the app's ability to honour outstanding obligations.

This detector is the *unguarded* version: it flags any reachable delete path regardless of who can take it. Pair it with `unprotected-deletable` (which additionally checks for the lack of a sender-creator guard) and `delete-funds-check` (which checks for a balance == min_balance guard).

## How it works

**Per-exit OnCompletion-guard form.** For each approval exit, the dominating branch predicates are examined; the exit is "guarded" if some predicate constrains `OnCompletion` to exclude 5 (DeleteApplication). Otherwise the exit is reported.

The QL form is deliberately conservative: dispatch via `match` / `switch` tables is not recognised as a guard (treated as if the exit were reachable from all OnCompletion values). The Python port preserves the same shape so its findings match the QL `.expected`.

## Files

- `isDeletable.ql` — CodeQL implementation. Uses `approvalExitUnguardedForAction` with `onCompletionDeleteApplication()`.
- `is_deletable.py` — Python port. Builds `PathPredicateAnalysis(prog)` and checks each approval exit's predicates for an `OnCompletion != 5` constraint.
- `isDeletable.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel real-world pair), `vuln-complex-dispatch.teal` / `fixed-complex-dispatch.teal` (multi-branch dispatch — the "fixed" variant is the deliberately-flagged case the strict QL form treats as a false positive, kept for parity).
