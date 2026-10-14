# Inner Transaction Non-Zero Fee

**Severity:** high · **Applies to:** application

## What it looks for

An application that emits an inner transaction explicitly setting `Fee` to a non-zero constant. The recommended pattern is fee 0 with the *caller* covering the fee pool — the application account doesn't get drained on repeated calls. Hardcoded non-zero fees in inner transactions are a common way to slowly drain the application's ALGO balance through attacker-triggered loops.

Dynamic (non-constant) fees aren't flagged. The detection catches the provably non-zero case: a non-zero integer constant, or a value flowing from `global MinTxnFee`.

## How it works

**Per-assignment finding** — every `itxn_field Fee` whose source operand resolves to a `Const` with `int` kind and a non-zero value, or flows from a `global MinTxnFee` read, is reported. The constant-propagation pass must have run for the operand to be classified as a const-int; the Python port triggers it explicitly.

## How to fix

Set the inner `Fee` to `int 0` so the caller covers it through fee pooling
(the outer transaction pays the extra fee). `global
MinTxnFee` as the inner fee is flagged: it is a non-zero protocol constant and
is paid from the app account.

<!-- verify: inner-txn-fee clean -->
```teal
#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 100000
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

<!-- verify: inner-txn-fee finding -->
```teal
#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 100000
itxn_field Amount
global MinTxnFee
itxn_field Fee
itxn_submit
int 1
return
```

```python
itxn.Payment(receiver=Txn.sender, amount=100_000, fee=0).submit()
```

If the app is meant to pay its own inner fees, suppress with
`// tealql-ignore: inner-txn-fee` on the `itxn_field Fee` line (or the line
above), or record the finding in a baseline (`--update-baseline` /
`--baseline PATH`).

## False positives

None documented. Every provably non-zero constant fee (and `global MinTxnFee`)
is reported, including on admin-only paths where the app paying is intended;
fees computed at runtime are never reported.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: Inner transaction with hardcoded non-zero fee
// Repeated calls drain the application account
txn OnCompletion
int 0
==
assert
itxn_begin
int 1
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 1000
itxn_field Fee
int 100000
itxn_field Amount
itxn_submit
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Inner transaction fee set to 0 — caller covers via fee pooling
txn OnCompletion
int 0
==
assert
itxn_begin
int 1
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 0
itxn_field Fee
int 100000
itxn_field Amount
itxn_submit
int 1
return
```

## Files

- `inner_txn_fee.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/inner_txn_fee/`, one directory per case.
