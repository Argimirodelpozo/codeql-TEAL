# Missing Transaction Type Restriction

**Severity:** high · **Applies to:** logicsig

## What it looks for

A contract — especially a LogicSig — that doesn't restrict `txn TypeEnum` (or the deprecated `Type` string field). Without this check, a LogicSig designed to approve a single payment may also approve unrelated transaction types (asset transfers, application calls, key registration, asset config) — every transaction type carries its own field set, including `AssetCloseTo`, `CloseRemainderTo`, `RekeyTo`, that may now be exploitable.

## How it works

**Per approving exit, every path.** Each approving exit is judged separately and reported when some path from the program entry reaches it without crossing a block that ENFORCES a comparison of `TypeEnum` or the legacy `Type` (either one counts) — the comparison's result reaching an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects. Checks placed per branch count as long as every path to the exit crosses one; scratch, phi and `proto` frame hops are followed. Only the SIGNED transaction's own field counts: `txn F`, `txn GroupIndex; gtxns F`, or `gtxn N F` when `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) is pinned. A program with three approving exits, one of them unchecked, yields one finding at that exit.

## How to fix

Compare `txn TypeEnum` (or the legacy `txn Type`) and enforce the result (`assert`, `return`, or a `bz`/`bnz` to a rejecting exit) on every path to every approving exit; either field counts. `txn GroupIndex; gtxns TypeEnum` and `gtxn N TypeEnum` under a `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) pin also count. Not credited: a dropped comparison, a `||` whose other arm does not also constrain the type, or a sibling's `gtxn N TypeEnum` on an unpinned index. The compared value is not inspected, so compare against the one type the logicsig is meant to approve.

<!-- verify: tx-type-check clean -->
```teal
#pragma version 8
txn TypeEnum
int pay
==
txn Amount
int 1000000
<=
&&
return
```

<!-- verify: tx-type-check finding -->
```teal
#pragma version 8
txn Amount
int 1000000
<=
return
```

```python
assert Txn.type_enum == TransactionType.Payment
```

If an exit really accepts any transaction type, put `// tealql-ignore: tx-type-check` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`; an app is always invoked as `appl`), but `tealql detections FILE --detector tx-type-check` runs it regardless of mode. Use `--mode app` / `--mode auto` with `--all`.
- Otherwise none documented. The type is not inferred from type-specific field checks (e.g. a `Receiver`/`Amount` bound), so such a logicsig is still reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No transaction type check — any type accepted
txn Amount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn RekeyTo
global ZeroAddress
==
&&
// Missing: txn TypeEnum == int pay (or expected type)
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Transaction type explicitly restricted to payment (type 1)
txn TypeEnum
int 1
==
txn Amount
int 1000000
<=
&&
txn Fee
global MinTxnFee
<=
&&
txn RekeyTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `src/tealql/security/detections/tx-type-check/tx_type_check.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/tx-type-check/`.
