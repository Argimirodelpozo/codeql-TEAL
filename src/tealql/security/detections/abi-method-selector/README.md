# Unvalidated ABI Method Selector

**Severity:** medium · **Applies to:** application

## What it looks for

An ABI application routes on the method selector in `txna ApplicationArgs 0` — comparing it to each method's 4-byte signature hash and rejecting anything unrecognised. If an approval exit is reachable *without* the selector being checked — a bare `int 1; return` fall-through past the dispatch, or a router that routes but never rejects an unknown selector — a caller can reach application logic the method table was supposed to gate.

## How it works

The detector is scoped to ABI-shaped apps: if the program never reads `txna ApplicationArgs 0`, it isn't doing method dispatch and nothing is flagged. For such apps it checks *each* approving exit, and treats an exit as protected when EITHER:

1. **Enforcement** — a selector comparison whose result reaches enforcement (`assert` / branch-to-`err`) on every path to the exit (`common.approval_exit_protected_for_arg_reads`); or
2. **Matched-selector edge** — the path predicate at the exit proves the selector equals a specific constant, so the exit is reached only because the selector matched a known method. This covers the `txna ApplicationArgs 0; match m0 m1 …; err` router shape and the `selector == M; bnz handler` shape: reaching a handler means the selector matched, so only the final fall-through `err` rejects an unknown selector.

Case 2 uses the same path-predicate reasoning as the OnCompletion match/switch guard recognition (`common.approval_exit_guarded_for_action`), which removes the earlier imprecision where a correct multi-method router had its handlers flagged. This is an SSA / path-predicate detector, not part of the lifted-IR family.

## Examples

Vulnerable — the detector flags this (the selector is read, discarded, and never checked before approval):

```teal
#pragma version 10
txna ApplicationArgs 0
pop
int 1
return
```

Safe — the detector stays quiet (the selector is pinned to a known method and enforced):

```teal
#pragma version 10
txna ApplicationArgs 0
byte 0x12345678
==
assert
int 1
return
```

## Files

- `abi_method_selector.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under `tests/tealtools/sec_guide/abi_method_selector/`, one directory per case; a `vuln` / `safe` precision-and-recall corpus lives under `tests/benchmark/abi-method-selector/`.
