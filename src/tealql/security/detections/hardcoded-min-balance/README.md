# Hardcoded Minimum Balance

**Severity:** medium · **Applies to:** application & logicsig

## What it looks for

A contract that subtracts a hardcoded constant from the account balance — i.e., uses `balance` followed (eventually) by `- N` where `N` is a literal int. The pattern is meant to compute "free balance above min_balance," but a hardcoded constant becomes stale: any opt-in to a new asset / application raises the actual min_balance, leaving the constant too low. Worse, the AVM panics on underflow, so the contract can become permanently unreachable once the real min_balance exceeds the hardcoded value.

The correct pattern is to use the `min_balance` opcode (a dynamic per-account computation), not a literal.

## How it works

Pattern match: find a `balance` opcode and a `-` opcode in the same program where the `-` consumes a literal int. Then *globally* require that the program contains no `min_balance` opcode (its presence anywhere is taken as evidence the dev knew about the dynamic form and is using it elsewhere).

This is a heuristic — the `balance` and `-` aren't required to be data-connected, only co-resident. The match-anywhere `min_balance` exemption is also coarse. False positives on contracts that subtract for unrelated reasons are possible; tightening this is a follow-up.

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
