# Missing GroupSize Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that uses `gtxn N <FIELD>` (absolute group-index access) but never compares `Global.GroupSize` against a specific value. Absolute `gtxn N` indices reference fixed positions within a transaction group — if the group's *actual* size isn't checked, an attacker can submit a longer group with crafted padding transactions at index N to satisfy the contract's assertions while doing something completely different at other positions.

Per-position constraints are meaningful only when the group's shape is locked down by a `GroupSize == K` check.

## How it works

**Per-opcode finding** — every `gtxn` (or `gtxna` / `gtxnsa` / family) is reported if `hasGroupSizeCheck()` is false anywhere in the program. The check is "is there *any* comparison against `Global.GroupSize`," not "does a GroupSize check dominate this `gtxn`." False positives on contracts that use stack-indexed `gtxns` (rather than absolute `gtxn N`) are possible.

## Files

- `group_size_check.py` — Python port. Walks `prog.assignments` for `gtxn`-family ops and any `==` / `!=` / `<` / etc. comparison against `global GroupSize`.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel pair), `vuln-conditional-gtxn.teal` (conditional `gtxn`), `vuln-gtxn-in-subroutine.teal` / `fixed-gtxn-in-subroutine.teal` (subroutine-encapsulated `gtxn`).
