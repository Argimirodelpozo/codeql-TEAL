# Updatable Without Timelock

**Severity:** medium · **Applies to:** application

## What it looks for

A stateful application where (a) an approval path is reachable under `OnCompletion == UpdateApplication`, *and* (b) a sender == creator guard *does* dominate the path (the basic protection is in place), *but* (c) the program nowhere uses a timestamp comparison — there's no built-in delay between an upgrade decision and its execution.

The "creator can rugpull instantly" pattern: the contract isn't open to everyone (creator-only), but creator users have no way of detecting an imminent upgrade and exiting beforehand.

## How it works

Three conjoined conditions per approval exit:
1. Approval exit reachable under `OnCompletion == 4`.
2. `senderCreatorGuardDominates` holds (the basic creator-only gate is present — opposite polarity from `unprotected-updatable`).
3. Some entry path to the exit does not cross a block that ENFORCES a comparison consuming a `global LatestTimestamp` or `global Round` read.

Condition (3) is per exit: a deadline in another arm does not cover the Update arm, and a timestamp that is only stored, logged, or compared with the result dropped is not a delay.

## How to fix

Make the creator-only Update arm wait for a delay the creator announced earlier: compare `global LatestTimestamp` (or `global Round`, for a delay in rounds) against a stored unlock time/round and enforce the result (`assert` or branch to a rejection) on every path to the Update exit. A timestamp that is only stored or logged, a comparison whose result is popped, or a deadline that lives in another arm is not credited.

<!-- verify: timelock-upgrade clean -->
```teal
#pragma version 10
txn OnCompletion
int UpdateApplication
==
bnz update
txn OnCompletion
int NoOp
==
assert
int 1
return
update:
txn Sender
global CreatorAddress
==
assert
global LatestTimestamp
byte "upgrade_unlock"
app_global_get
>=
assert
int 1
return
```

The same delay spelled in rounds (`global Round; byte "upgrade_unlock_round"; app_global_get; >=; assert`) is credited identically. Vulnerable counterpart:

<!-- verify: timelock-upgrade finding -->
```teal
#pragma version 10
txn OnCompletion
int UpdateApplication
==
bnz update
txn OnCompletion
int NoOp
==
assert
int 1
return
update:
txn Sender
global CreatorAddress
==
assert
int 1
return
```

```python
assert Global.latest_timestamp >= self.upgrade_unlock  # set by an earlier announce_upgrade() call
```

Give the Update arm its own exit: the delay must lie on every path into the flagged exit (see False positives). If an instant creator upgrade is an accepted trust assumption, suppress with `// tealql-ignore: timelock-upgrade` on the flagged exit line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- **Shared exit.** The delay is required on *every* entry path to the exit, not only the Update paths. When the Update arm (creator check + delay) and a non-Update arm share one `approve:` exit (`OnCompletion == UpdateApplication; bz done; …; done: int 1; return`), the non-Update path never crosses the delay and the exit is reported even though the update itself is delayed. Verified on the current tree; work-around: give the Update arm its own `int 1; return`.
- Conversely (a false negative): any enforced `LatestTimestamp` / `Round` comparison on the path is credited, including an app-expiry check (`global LatestTimestamp; int END; <; assert`) in the shared prologue that delays nothing (reproduced on the current tree).
- The round-based-delay FP (A11) is fixed.

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
