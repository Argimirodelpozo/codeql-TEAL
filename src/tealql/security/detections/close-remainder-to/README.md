# Missing CloseRemainderTo Validation

**Severity:** high · **Applies to:** logicsig

## What it looks for

A contract that processes ALGO payment transactions but never checks `txn CloseRemainderTo`. When `CloseRemainderTo` is non-zero, the AVM closes the sending account at the end of the transaction and sends the *entire ALGO balance* (minus the payment amount and fee) to the named address. An attacker can use this to fully drain the account.

## How it works

**Per approving exit, every path.** Each approving exit is judged separately and reported when some path from the program entry reaches it without crossing a block that ENFORCES a SAFE check of `CloseRemainderTo` — one that constrains it to `global ZeroAddress` or a fixed address (`==`, or a `!=` whose truth rejects) — a comparison against an `arg` the submitter supplies pins nothing; the check's result reaching an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects. Checks placed per branch count as long as every path to the exit crosses one; scratch, phi and `proto` frame hops are followed. Only the SIGNED transaction's own field counts: `txn F`, `txn GroupIndex; gtxns F`, or `gtxn N F` when `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) is pinned. A program with three approving exits, one of them unchecked, yields one finding at that exit.

## How to fix

Compare the signed transaction's own `CloseRemainderTo` against `global ZeroAddress` and enforce the result (`assert`, `return`, or a `bz`/`bnz` to a rejecting exit) on every path to every approving exit. `txn CloseRemainderTo`, `txn GroupIndex; gtxns CloseRemainderTo`, and `gtxn N CloseRemainderTo` under a `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) pin all count. Not credited: a comparison whose result is dropped (`pop`) or never reaches an `assert`/branch, a `||` whose other arm does not also constrain the field, and `gtxn N CloseRemainderTo` on an unpinned index. The compared value and polarity are not inspected, so write the check as `== global ZeroAddress` (or `== <the intended close-out address>`).

<!-- verify: close-remainder-to clean -->
```teal
#pragma version 8
txn TypeEnum
int pay
==
assert
txn CloseRemainderTo
global ZeroAddress
==
bz reject
txn Amount
int 1000000
<=
return
reject:
err
```

Still flagged — the comparison is computed and discarded:

<!-- verify: close-remainder-to finding -->
```teal
#pragma version 8
txn TypeEnum
int pay
==
assert
txn CloseRemainderTo
global ZeroAddress
==
pop
txn Amount
int 1000000
<=
return
```

```python
assert Txn.close_remainder_to == Global.zero_address
```

If an exit intentionally closes the account, put `// tealql-ignore: close-remainder-to` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`; an `appl` txn has no `CloseRemainderTo`), but `tealql detections FILE --detector close-remainder-to` runs it regardless of mode. Use `--mode app` / `--mode auto` with `--all`.
- Otherwise none documented. An exit that only approves non-`pay` transactions (via a `TypeEnum` restriction) is still reported if it lacks a `CloseRemainderTo` comparison: the detector does not reason about which fields a type makes inert.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No CloseRemainderTo check — all ALGO can be drained
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn CloseRemainderTo == global ZeroAddress
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: CloseRemainderTo validated against ZeroAddress
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn CloseRemainderTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `src/tealql/security/detections/close-remainder-to/close_remainder_to.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/close-remainder-to/`.
