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

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: Creator can update immediately — no timelock delay
// Users have no time to review new code or exit before upgrade
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
// Missing: LatestTimestamp >= announced_upgrade_time + delay
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Update requires timelock — 24h delay after announcement
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
// Enforce that current time >= announced upgrade time + 86400 (24 hours)
global LatestTimestamp
pushbytes "upgrade_timestamp"
app_global_get
int 86400
+
>=
assert
// Clear upgrade state after successful upgrade
pushbytes "upgrade_timestamp"
app_global_del
int 1
return
```

## Files

- `timelock_upgrade.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/timelock_upgrade/`, one directory per case.
