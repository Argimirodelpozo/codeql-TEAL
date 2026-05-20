# Updatable Without Timelock

**Severity:** medium · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == UpdateApplication`, *and* (b) a sender == creator guard *does* dominate the path (the basic protection is in place), *but* (c) the program nowhere uses a timestamp comparison — there's no built-in delay between an upgrade decision and its execution.

The "creator can rugpull instantly" pattern: the contract isn't open to everyone (creator-only), but creator users have no way of detecting an imminent upgrade and exiting beforehand.

## How it works

Three conjoined conditions per approval exit:
1. Approval exit reachable under `OnCompletion == 4`.
2. `senderCreatorGuardDominates` holds (the basic creator-only gate is present — opposite polarity from `unprotected-updatable`).
3. `hasTimestampCheck()` is false globally (no `Global.LatestTimestamp` comparison anywhere in the program).

This is a *contract-wide* gate on condition (3): the timestamp check just has to exist somewhere, not dominate the upgrade path. Tightening this is a follow-up.

## Files

- `timelockUpgrade.ql` — CodeQL implementation. Combines `approvalExitUnguardedForAction(onCompletionUpdateApplication)`, `senderCreatorGuardDominates`, and `not hasTimestampCheck()`.
- `timelock_upgrade.py` — Python port using the same three checks.
- `timelockUpgrade.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-complex-dispatch.teal` / `fixed-complex-dispatch.teal` (multi-branch dispatch).
