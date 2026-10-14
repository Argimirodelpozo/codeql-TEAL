# Unvalidated ABI Method Selector

**Severity:** medium · **Applies to:** application

## What it looks for

An ABI application routes on the method selector in `txna ApplicationArgs 0` — comparing it to each method's 4-byte signature hash and rejecting anything unrecognised. If an approval exit is reachable *without* the selector being checked — a bare `int 1; return` fall-through past the dispatch, or a router that routes but never rejects an unknown selector — a caller can reach application logic the method table was supposed to gate.

## How it works

The detector is scoped to apps that ROUTE on the selector: some instruction compares `txna ApplicationArgs 0` itself (or `btoi` of it) — `==`/`!=`, `match`, `switch`. A program that only reads arg 0 as data (a price, a name, `len(arg0) == 6`) has no method table and nothing is flagged. For routing apps it checks *each* approving exit, and treats an exit as protected when EITHER:

1. **Enforcement** — a selector comparison whose result reaches enforcement (`assert` / branch-to-`err`) on every path to the exit (`_field_protection.approval_exit_protected_for_arg_reads`); or
2. **Matched-selector edge** — the path predicate at the exit proves the selector equals a specific constant, so the exit is reached only because the selector matched a known method. This covers the `txna ApplicationArgs 0; match m0 m1 …; err` router shape and the `selector == M; bnz handler` shape: reaching a handler means the selector matched, so only the final fall-through `err` rejects an unknown selector.

A path is also closed by an edge proving the call is not a method call at all: the creation path (`txn ApplicationID == 0`) or `OnCompletion != NoOp` (OptIn / CloseOut / Update / Delete handlers dispatched on OnCompletion). All closures are per EDGE, over realizable paths (return stack through shared helpers).

Case 2 uses the same path-predicate reasoning as the OnCompletion match/switch guard recognition (`_action_guards.approval_exit_guarded_for_action`), which removes the earlier imprecision where a correct multi-method router had its handlers flagged. This is an SSA/path-predicate detector.

## How to fix

Reject unknown selectors: dispatch with `match` (or `selector == M; bnz handler`) and end the dispatch with `err`, so every handler is reached only on a matched selector and everything else fails. Alternatively `assert` the selector against a value the caller cannot choose (a constant, or state the program controls). Route bare calls under `txn NumAppArgs == 0` (`txn NumAppArgs; bz bare_routing`, the PuyaPy/PyTeal shape): those exits carry no selector and are credited. A selector compared against another caller argument (`txna ApplicationArgs 1`) is not a check.

<!-- verify: abi-method-selector clean -->
```teal
#pragma version 10
txn NumAppArgs
bz bare_routing          // bare call (no selector): route on OnCompletion
method "hello(string)string"
method "bye(string)string"
txna ApplicationArgs 0
match hello bye
err                      // unknown selector: reject
hello:
int 1
return
bye:
int 1
return
bare_routing:            // only a bare create is accepted
txn OnCompletion
!
txn ApplicationID
!
&&
return
```

Vulnerable counterpart — the `match` falls through to an approval instead of `err`:

<!-- verify: abi-method-selector finding -->
```teal
#pragma version 10
method "hello(string)string"
txna ApplicationArgs 0
match hello
int 1                    // unknown selector falls through and approves
return
hello:
int 1
return
```

`algopy.ARC4Contract` emits exactly the clean shape (`match …; err`, bare calls behind `txn NumAppArgs; bz`); this finding on PuyaPy output usually means a hand-written `approval_program` override. If an exit is meant to accept any selector, suppress with `// tealql-ignore: abi-method-selector` on the flagged exit line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- **`match` operand order.** `match` compares the TOP of the stack against the cases below it; the selector is credited only as that top value (`method …; txna ApplicationArgs 0; match …`, as every compiler emits it). A hand-written single-case `txna ApplicationArgs 0; method …; match h; err` is semantically equivalent but its handler is reported. Verified on the current tree.
- A `btoi(arg0)` integer-tag dispatch (Reach) is in scope but its `==` pins are not credited as selector pins (`reach-btoi-dispatch`).
- Fixed 2026-10-10 (field-measured): create / non-NoOp OnCompletion paths (`lifecycle-oc-path`, 211 mainnet cells) and apps that never route on arg 0 (`no-method-dispatch`, 123 cells).
- Fixed in `docs/REVIEW_2026_10_10.md`: A7 (bare `NumAppArgs == 0` handlers on real PuyaPy / PyTeal / TEALScript output — rows on 180/231 mainnet probes).

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
