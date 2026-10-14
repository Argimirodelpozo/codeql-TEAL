# Missing AssetCloseTo Validation

**Severity:** high · **Applies to:** logicsig

## What it looks for

A contract that processes asset transfers but never checks `txn AssetCloseTo`. The `AssetCloseTo` field, when non-zero, transfers *all* remaining units of the named asset from the spending account to the address it points at — so an unchecked contract lets an attacker drain an asset balance in a single transaction.

## How it works

**Whole program, every path.** One finding (no anchor line) when some approving exit is reachable along a path that does not cross a block ENFORCING a SAFE pin (to `global ZeroAddress` or a fixed address; `AssetCloseTo != Sender` pins nothing) of the SIGNED transaction's own `AssetCloseTo` (`txn AssetCloseTo`, `txn GroupIndex; gtxns AssetCloseTo`, or `gtxn N AssetCloseTo` under a `txn GroupIndex == N` / `global GroupSize == 1` pin). Enforcing means the result reaches an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects; per-branch checks count as long as every approving path crosses one. When the only enforced check is a `gtxn N AssetCloseTo` on an unpinned index, the finding says so specifically. A program with no approving exit is not reported.

## How to fix

Compare the signed transaction's own `AssetCloseTo` against `global ZeroAddress` and enforce the result on every approving path (`assert`, or a `bz`/`bnz` to a rejecting exit). `txn AssetCloseTo`, `txn GroupIndex; gtxns AssetCloseTo`, and `gtxn N AssetCloseTo` under a `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) pin all count. A `gtxn N AssetCloseTo` check on an UNPINNED index is reported with a dedicated message: it validates a sibling, not the signer. A comparison whose result is dropped, or a `||` whose other arm does not constrain the field, is not a check.

<!-- verify: asset-close-to clean -->
```teal
#pragma version 8
txn TypeEnum
int axfer
==
assert
txn AssetCloseTo
global ZeroAddress
==
assert
txn AssetAmount
int 1000
<=
return
```

Still flagged — `gtxn 1` is a sibling, and nothing pins `txn GroupIndex == 1`:

<!-- verify: asset-close-to finding -->
```teal
#pragma version 8
gtxn 1 AssetCloseTo
global ZeroAddress
==
assert
txn AssetAmount
int 1000
<=
return
```

```python
assert Txn.asset_close_to == Global.zero_address
```

The finding is whole-program (no anchor line): to accept it, put `// tealql-ignore: asset-close-to` on any line before the first instruction (e.g. right after `#pragma version`), or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`), but `tealql detections FILE --detector asset-close-to` runs it regardless of mode. Use `--mode app` / `--mode auto` with `--all`.
- A logicsig that never approves an `axfer` (e.g. restricted to `TypeEnum == pay`) but has no `AssetCloseTo` comparison is still reported: the detector does not reason about which fields a type makes inert. Programs with no approving exit are not reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No AssetCloseTo check — every unit of the asset can be drained
txn AssetAmount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn AssetCloseTo == global ZeroAddress
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: AssetCloseTo validated against ZeroAddress
txn AssetAmount
int 1000000
<=
txn Fee
global MinTxnFee
<=
&&
txn AssetCloseTo
global ZeroAddress
==
&&
assert
int 1
return
```

## Files

- `src/tealql/security/detections/asset-close-to/asset_close_to.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/asset-close-to/`.
