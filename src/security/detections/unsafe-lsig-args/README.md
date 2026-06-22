# Unsafe LogicSig Argument Usage

**Severity:** high · **Applies to:** logicsig

## What it looks for

A LogicSig that uses `arg N` (or `args`) opcodes as one side of an equality / inequality comparison. LogicSig args come from the calling transaction's `Args` field — i.e., they're attacker-controlled. Comparing an attacker-controlled value to a constant lets the attacker satisfy any equality precondition the LogicSig sets, sidestepping authorisation that depends on the comparison.

The correct pattern uses `txn Sender` (or fields covered by the AVM signature) for auth-relevant comparisons, not args.

## How it works

**Per-opcode finding** — every `arg N` (or `args`) read that flows into a comparison opcode (`==`, `!=`, `<`, `>`, `<=`, `>=`) is reported. The detection is data-flow-based: the arg's SSAVar has to actually be one of the comparison's input operands, not just appear in the same program.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 8
// VULNERABLE: Using LogicSig arg as password for access control
// Args are visible on-chain and not covered by signatures
arg_0
pushbytes "s3cret_p4ssw0rd"
==
assert
txn Amount
int 500000
<=
assert
txn Fee
global MinTxnFee
<=
assert
int 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 8
// FIXED: Use deterministic checks instead of args for authorization
// All security-relevant values are baked into the bytecode
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
txn CloseRemainderTo
global ZeroAddress
==
&&
txn Receiver
addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
==
&&
assert
int 1
return
```

## Files

- `unsafe_lsig_args.py` — the detector.

Test fixtures — `vuln` / `fixed` `.teal` programs and the expected detector output — live under
`tests/tealtools/sec_guide/unsafe_lsig_args/`, one directory per case.
