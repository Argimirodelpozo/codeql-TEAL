# Missing Fee Validation

**Severity:** high · **Applies to:** logicsig

## What it looks for

A LogicSig that doesn't bound `txn Fee`. Without an upper bound on the fee, an attacker can submit transactions signed by the LogicSig with absurdly inflated fees (up to the account balance), draining the spending account through fee extraction rather than the payment amount.

## How it works

**Per approving exit, every path.** Each approving exit is judged separately and reported when some path from the program entry reaches it without crossing a block that ENFORCES a SAFE check of `Fee` — one that bounds it from ABOVE by a trusted value (`== K`, `< K`, `<= K`, `K >= Fee`, `Fee; !`, with `K` a constant / `global MinTxnFee` / arithmetic of those) — `Fee > 0` caps nothing; the check's result reaching an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects. Checks placed per branch count as long as every path to the exit crosses one; scratch, phi and `proto` frame hops are followed. Only the SIGNED transaction's own field counts: `txn F`, `txn GroupIndex; gtxns F`, or `gtxn N F` when `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) is pinned. A `Fee; !` zero-test counts as a comparison. A program with three approving exits, one of them unchecked, yields one finding at that exit.

## How to fix

Compare the signed transaction's own `Fee` against a bound and enforce the result (`assert`, `return`, or a `bz`/`bnz` to a rejecting exit) on every path to every approving exit. `txn Fee`, `txn GroupIndex; gtxns Fee`, `gtxn N Fee` under a `txn GroupIndex == N` pin, and `gtxn 0 Fee` under `global GroupSize == 1` (a one-transaction group has only position 0, so it IS the signer's own fee) all count, as does the compiled `Fee; !; assert` (fee == 0). Not credited: `gtxn N Fee` on an unpinned index (a sibling's fee), a dropped comparison, or a `||` whose other arm does not also constrain `Fee`. The detector does not inspect the bound or polarity (`txn Fee > 0` silences it), so write an upper bound.

<!-- verify: fee-validation clean -->
```teal
#pragma version 8
global GroupSize
int 1
==
assert
gtxn 0 Fee
global MinTxnFee
<=
assert
int 1
return
```

Still flagged — without the `GroupSize == 1` pin, `gtxn 0` may be a sibling:

<!-- verify: fee-validation finding -->
```teal
#pragma version 8
gtxn 0 Fee
global MinTxnFee
<=
assert
int 1
return
```

```python
assert Txn.fee <= Global.min_txn_fee
```

If an exit is meant to accept any fee, put `// tealql-ignore: fee-validation` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`), but `tealql detections FILE --detector fee-validation` runs it regardless of mode. Use `--mode app` / `--mode auto` with `--all`.
- Otherwise none documented. (`GroupSize == 1; gtxn 0 Fee`, formerly a false positive, is credited.)

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: txn Fee is never bounded — an attacker can set an
// enormous fee and drain the account
txn Amount
int 1000000
<=
// Missing: txn Fee <= global MinTxnFee
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: txn Fee bounded to the network minimum
txn Fee
global MinTxnFee
<=
txn Amount
int 1000000
<=
&&
assert
int 1
return
```

## Files

- `src/tealql/security/detections/fee-validation/fee_validation.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/fee-validation/`.
