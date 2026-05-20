# Missing GroupSize Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that uses `gtxn N <FIELD>` (absolute group-index access) but never compares `Global.GroupSize` against a specific value. Absolute `gtxn N` indices reference fixed positions within a transaction group — if the group's *actual* size isn't checked, an attacker can submit a longer group with crafted padding transactions at index N to satisfy the contract's assertions while doing something completely different at other positions.

Per-position constraints are meaningful only when the group's shape is locked down by a `GroupSize == K` check.

## How it works

**Per-opcode finding** — every `gtxn` (or `gtxna` / `gtxnsa` / family) is reported if `hasGroupSizeCheck()` is false anywhere in the program. The check is "is there *any* comparison against `Global.GroupSize`," not "does a GroupSize check dominate this `gtxn`." False positives on contracts that use stack-indexed `gtxns` (rather than absolute `gtxn N`) are possible.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: indexes gtxn 1 by absolute position without pinning
// GroupSize — an attacker can pad the group with extra transactions
gtxn 1 TypeEnum
int axfer
==
// Missing: global GroupSize == 2
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: GroupSize pinned before relying on an absolute gtxn index
global GroupSize
int 2
==
gtxn 1 TypeEnum
int axfer
==
&&
assert
int 1
return
```

## Files

- `group_size_check.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs, their built
CodeQL DBs, and the expected detector output — live under
`tests/tealtools/sec_guide/group_size_check/`, one directory per case.
