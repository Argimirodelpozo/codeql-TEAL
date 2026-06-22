# Inner Transaction Sets CloseRemainderTo / RekeyTo / AssetCloseTo

**Severity:** high · **Applies to:** application

## What it looks for

An application that emits an inner transaction (`itxn_submit`) which sets any of `CloseRemainderTo`, `RekeyTo`, or `AssetCloseTo` via `itxn_field`. These three fields drain or transfer signing authority — an application's account is much more attacker-controllable than a single-tx escrow, so any inner-tx setter of these fields is almost always a bug or a deliberate footgun.

The correct pattern is to omit the field entirely (it defaults to the zero address), not to set it.

## How it works

**Per-assignment finding** — every `itxn_field <FIELD>` opcode where `FIELD` is one of the three dangerous names is reported, regardless of the value being assigned. No path-sensitivity is applied: even an `itxn_field RekeyTo` guarded behind a `bz` that's never taken still flags. This is intentional — the false-positive cost is low because the correct pattern is to never write these fields.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: Inner transaction sets CloseRemainderTo to user-controlled address
// Attacker can drain the application's entire balance
txn OnCompletion
int 0
==
assert
itxn_begin
int 1
itxn_field TypeEnum
txn Sender
itxn_field Receiver
txn Sender
itxn_field CloseRemainderTo
int 0
itxn_field Fee
itxn_submit
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Inner transaction omits CloseRemainderTo and RekeyTo entirely
// These fields default to zero address when omitted
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

- `inner_txn_close_rekey.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/inner_txn_close_rekey/`, one directory per case.
