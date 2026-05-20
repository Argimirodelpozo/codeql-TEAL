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

## Files

- `unprotected_updatable.py` — Python port using the same two checks.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-dispatch-table.teal` / `fixed-dispatch-table.teal` (dispatch tables), `vuln-nested-dispatch.teal` (nested dispatch through a subroutine).
