# Hardcoded Minimum Balance

**Severity:** medium · **Applies to:** application & logicsig

## What it looks for

A contract that subtracts a hardcoded constant from the account balance — i.e., uses `balance` followed (eventually) by `- N` where `N` is a literal int. The pattern is meant to compute "free balance above min_balance," but a hardcoded constant becomes stale: any opt-in to a new asset / application raises the actual min_balance, leaving the constant too low. Worse, the AVM panics on underflow, so the contract can become permanently unreachable once the real min_balance exceeds the hardcoded value.

The correct pattern is to use the `min_balance` opcode (a dynamic per-account computation), not a literal.

## How it works

Pattern match: find a `balance` opcode and a `-` opcode in the same program where the `-` consumes a literal int. Then *globally* require that the program contains no `min_balance` opcode (its presence anywhere is taken as evidence the dev knew about the dynamic form and is using it elsewhere).

This is a heuristic — the `balance` and `-` aren't required to be data-connected, only co-resident. The match-anywhere `min_balance` exemption is also coarse. False positives on contracts that subtract for unrelated reasons are possible; tightening this is a follow-up.

## Files

- `hardcodedMinBalance.ql` — CodeQL implementation. Uses `balanceMinusHardcodedConstant` from `SecGuideCommon.qll` plus the `min_balance` anywhere-exemption.
- `hardcoded_min_balance.py` — Python port. Walks `prog.assignments` for the opcode triplet and a literal-int operand on the `-`.
- `hardcodedMinBalance.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair — fixed uses `min_balance`).
