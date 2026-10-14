# Missing RekeyTo Validation

**Severity:** high · **Applies to:** logicsig

## What it looks for

A contract with at least one approval exit that doesn't validate `txn RekeyTo` against the zero address. When `RekeyTo` is set to a non-zero address, the AVM permanently rebinds the signing key of the spending account to that address — an attacker can effectively steal an escrow account, a delegated LogicSig, or a stateful contract's controllable address with one well-crafted transaction.

## How it works

**Per approving exit, every path.** Each approving exit is judged separately and reported when some path from the program entry reaches it without crossing a block that ENFORCES a SAFE check of `RekeyTo` — one that constrains it to `global ZeroAddress` or a fixed address (`==`, or a `!=` whose truth rejects) — `RekeyTo != Sender` compares the field and pins nothing; the check's result reaching an `assert`, the approving `return`, or a `bz`/`bnz` whose other side rejects. Checks placed per branch count as long as every path to the exit crosses one; scratch, phi and `proto` frame hops are followed. Only the SIGNED transaction's own field counts: `txn F`, `txn GroupIndex; gtxns F`, or `gtxn N F` when `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) is pinned. A program with three approving exits, one of them unchecked, yields one finding at that exit.

## How to fix

Compare the signed transaction's own `RekeyTo` against `global ZeroAddress` and enforce the result (`assert`, `return`, or a `bz`/`bnz` to a rejecting exit) on every path to every approving exit. `txn RekeyTo`, `txn GroupIndex; gtxns RekeyTo`, and `gtxn N RekeyTo` under a `txn GroupIndex == N` (or `global GroupSize == 1`, for `N = 0`) pin all count. Not credited: a comparison whose result is dropped, a `||` whose other arm does not also constrain `RekeyTo`, and `gtxn N RekeyTo` on an unpinned index (a sibling, not the signer). The detector does not inspect the compared value or polarity, so make sure the check you write is `== global ZeroAddress`.

<!-- verify: rekey-to clean -->
```teal
#pragma version 8
txn TypeEnum
int pay
==
assert
txn RekeyTo
global ZeroAddress
==
assert
txn Amount
int 1000000
<=
return
```

Still flagged — the `||` lets a small payment approve with any `RekeyTo`:

<!-- verify: rekey-to finding -->
```teal
#pragma version 8
txn TypeEnum
int pay
==
assert
txn RekeyTo
global ZeroAddress
==
txn Amount
int 1000000
<=
||
return
```

```python
assert Txn.rekey_to == Global.zero_address
```

If the exit is meant to approve a rekey, put `// tealql-ignore: rekey-to` on the flagged exit line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Running the detector on an application program: it is scoped to logicsigs (`applies_to = {logicsig}`), but `tealql detections FILE --detector rekey-to` runs it regardless of mode. On an app, `RekeyTo` is the caller's own signed field; ignore the finding or scan with `--mode app` / `--mode auto` under `--all`.
- Otherwise none documented. Each approving exit is judged independently, so a contract that rejects every rekeying transaction by a means other than a `RekeyTo` comparison (e.g. a `TypeEnum` restriction to a type the signer would never rekey with) is still reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: No RekeyTo check — attacker can rekey account to themselves
txn Amount
int 500000
<=
txn Fee
global MinTxnFee
<=
&&
// Missing: txn RekeyTo == global ZeroAddress
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: RekeyTo validated against ZeroAddress
txn Amount
int 500000
<=
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

- `src/tealql/security/detections/rekey-to/rekey_to.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/rekey-to/`.
