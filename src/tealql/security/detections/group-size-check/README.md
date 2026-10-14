# Missing GroupSize Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract that uses `gtxn N <FIELD>` (absolute group-index access) but never compares `Global.GroupSize` against a specific value. Absolute `gtxn N` indices reference fixed positions within a transaction group — if the group's *actual* size isn't checked, an attacker can submit a longer group with crafted padding transactions at index N to satisfy the contract's assertions while doing something completely different at other positions.

Per-position constraints are meaningful only when the group's shape is locked down by a `GroupSize == K` check.

## How it works

Judges an approving exit only when a realizable path reaches it THROUGH an ABSOLUTE group-index read (`gtxn` / `gtxna` / `gtxnas`), following calls into helpers with a return stack; stack-indexed `gtxns` reads are AVM-bounds-checked and do not trigger it. **Per approving exit, every path.** Each in-scope exit is reported when some realizable path from the program entry reaches it without crossing a block that ENFORCES a SAFE bound on `global GroupSize` — `== K`, `< K` or `<= K` against a constant (an upper bound; `GroupSize >= K` caps nothing) — the comparison's result reaching an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects. Checks placed per branch count as long as every path to the exit crosses one; scratch, phi and `proto` frame hops are followed. A program with three approving exits, one of them unchecked, yields one finding at that exit.

## How to fix

Pin the group size with a comparison of `global GroupSize` that is enforced (`assert`, `return`, or a `bz`/`bnz` to a rejecting exit) on every path to every approving exit. The detector runs only when the program reads an absolute index (`gtxn`/`gtxna`/`gtxnas`); stack-indexed `gtxns` reads are AVM-bounds-checked and do not trigger it. Any enforced `GroupSize` comparison is credited — including `>=` — so write `== K` yourself if padding must be ruled out. Not credited: a dropped comparison, or a `||` whose other arm does not also constrain `GroupSize`.

<!-- verify: group-size-check clean -->
```teal
#pragma version 8
global GroupSize
int 2
==
assert
gtxn 1 TypeEnum
int axfer
==
return
```

<!-- verify: group-size-check finding -->
```teal
#pragma version 8
gtxn 1 TypeEnum
int axfer
==
return
```

```python
assert Global.group_size == 2
```

If the contract tolerates extra group members by design, put `// tealql-ignore: group-size-check` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- An absolute read of the program's OWN transaction is still a trigger: `txn GroupIndex; int 0; ==; assert; gtxn 0 Fee ...` is reported without a `GroupSize` comparison, although `gtxn 0` is the current transaction and padding does not change it. Prefer `txn Fee` there, or suppress.
- Fixed 2026-10-10 (field-measured): an absolute `gtxn N` read anywhere no longer puts every exit in scope (`exit-path-reads-no-absolute-gtxn`, 195 mainnet cells), and a bound asserted before a shared helper's call is no longer lost through another caller's `retsub` edge (`groupsize-bounded-on-path`).

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

- `src/tealql/security/detections/group-size-check/group_size_check.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/group-size-check/`.
