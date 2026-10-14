# Unsafe LogicSig Argument Usage

**Severity:** high · **Applies to:** logicsig

## What it looks for

A LogicSig that uses `arg N` (or `args`) opcodes as one side of an equality / inequality comparison. LogicSig args come from the calling transaction's `Args` field — i.e., they're attacker-controlled. Comparing an attacker-controlled value to a constant lets the attacker satisfy any equality precondition the LogicSig sets, sidestepping authorisation that depends on the comparison.

The correct pattern uses `txn Sender` (or fields covered by the AVM signature) for auth-relevant comparisons, not args.

## How it works

**Per-arg finding** — every `arg N` / `arg_N` / `args` read whose value reaches an equality-key op (`==`, `b==`, `!=`, `b!=`, `match`, `switch`) is reported once, at the `arg` line. Reachability is over the interprocedural taint graph (def-use, phi, scratch and `proto` frame edges), so an arg stashed in scratch, passed through subroutines or hashed before the comparison is still caught. Ordering comparisons (`<`, `>`, `<=`, `>=`) and verify opcodes are not sinks.

## How to fix

Never authorise with an equality on a logicsig argument (`==`, `b==`, `!=`, `b!=`, `match`, `switch`), even after hashing. Authenticate with a signature instead: pass the signature as an arg and verify it against a public key baked into the program (`ed25519verify`, `ecdsa_verify`), with the authorisation itself coming from fields the signer commits to. The detector follows the arg through scratch, subroutines, and hashing, but an arg that reaches only non-equality ops (a verify opcode, an ordering comparison such as `<`) is not reported.

<!-- verify: unsafe-lsig-args clean -->
```teal
#pragma version 8
txn TxID
arg 0
addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
ed25519verify
assert
txn Fee
global MinTxnFee
<=
return
```

Still flagged — hashing does not make the comparison a credential:

<!-- verify: unsafe-lsig-args finding -->
```teal
#pragma version 8
arg 0
sha256
byte 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
==
return
```

```python
assert op.ed25519verify(Txn.tx_id, op.arg(0), TemplateVar[Bytes]("SIGNER_PK"))
```

If the equality is not an access-control gate (see False positives), put `// tealql-ignore: unsafe-lsig-args` on the flagged `arg` line (or the line above it), or record the finding in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

The detector flags ANY arg value reaching an equality-key op, not only access-control gates:

- A length/format check on an arg (`arg 0; len; int 64; ==; assert`) is reported.
- An arg used only to select a code path (`arg 0; btoi; switch ...` / `match`) is reported, even when every selected path is independently validated.
- A hash-time-lock preimage check (`arg 0; sha256; byte <hash>; ==`) is reported by design: the preimage is public once revealed, so this is only safe when the logicsig also bounds what a replay can do.

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

- `src/tealql/security/detections/unsafe-lsig-args/unsafe_lsig_args.py` — the detector.

Precision / recall fixtures — `vuln/` and `safe/` `.teal` programs — live under `tests/benchmark/unsafe-lsig-args/`.
