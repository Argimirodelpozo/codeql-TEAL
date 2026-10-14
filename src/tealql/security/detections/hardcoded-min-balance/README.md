# Hardcoded Minimum Balance

**Severity:** medium · **Applies to:** application

## What it looks for

A contract that subtracts a hardcoded constant from the account balance — i.e., uses `balance` followed (eventually) by `- N` where `N` is a literal int. The pattern is meant to compute "free balance above min_balance," but a hardcoded constant becomes stale: any opt-in to a new asset / application raises the actual min_balance, leaving the constant too low. Worse, the AVM panics on underflow, so the contract can become permanently unreachable once the real min_balance exceeds the hardcoded value.

The correct pattern is to use the `min_balance` opcode (a dynamic per-account computation), not a literal.

## How it works

Value flow: a `-` whose one operand flows from a `balance` read (through phi / scratch / proto-frame) and whose other operand is a known integer constant is reported. The whole detector is silenced when the program contains any `min_balance` opcode (its presence anywhere is taken as evidence the dev knew about the dynamic form and is using it elsewhere).

## How to fix

Subtract the account's current `min_balance` instead of a literal.

<!-- verify: hardcoded-min-balance clean -->
```teal
#pragma version 10
// pay out only the balance above the account's CURRENT minimum
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
global CurrentApplicationAddress
balance
global CurrentApplicationAddress
min_balance
-
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

<!-- verify: hardcoded-min-balance finding -->
```teal
#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
global CurrentApplicationAddress
balance
int 100000
-
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

```python
app = Global.current_application_address
amount = app.balance - app.min_balance
```

Suppress an intended finding with `// tealql-ignore: hardcoded-min-balance` on
the flagged `-` line (or the line above), or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

Any `balance - <constant>` is flagged, whatever the constant means — a fee
reserve or an intentional buffer subtracted from a balance reads the same as a
hardcoded minimum. The reverse is coarse too: one `min_balance` anywhere in the
program silences every subtraction.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: Hardcoded minimum balance of 100000 microALGO
// Breaks when contract creates boxes or opts into assets
txn OnCompletion
int 0
==
assert
global CurrentApplicationAddress
balance
int 100000
-
store 0
load 0
int 0
>
assert
itxn_begin
int 1
itxn_field TypeEnum
txn Sender
itxn_field Receiver
load 0
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Dynamic minimum balance using min_balance opcode
txn OnCompletion
int 0
==
assert
global CurrentApplicationAddress
balance
global CurrentApplicationAddress
min_balance
-
store 0
load 0
int 0
>
assert
itxn_begin
int 1
itxn_field TypeEnum
txn Sender
itxn_field Receiver
load 0
itxn_field Amount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

## Files

- `hardcoded_min_balance.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/hardcoded_min_balance/`, one directory per case.
