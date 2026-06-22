# Inner Transaction Non-Zero Fee

**Severity:** high · **Applies to:** application

## What it looks for

An application that emits an inner transaction explicitly setting `Fee` to a non-zero constant. The recommended pattern is fee 0 with the *caller* covering the fee pool — the application account doesn't get drained on repeated calls. Hardcoded non-zero fees in inner transactions are a common way to slowly drain the application's ALGO balance through attacker-triggered loops.

Dynamic (non-constant) fees aren't flagged. The detection deliberately only catches the static-non-zero case to match the QL form.

## How it works

**Per-assignment finding** — every `itxn_field Fee` whose source operand resolves to a `Const` with `int` kind and a non-zero value is reported. The constant-propagation pass must have run for the operand to be classified as a const-int; the Python port triggers it explicitly.

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
