# partial-tainted-fund-flow

**Byte-precise fund-flow — the partial-validation bypass.**

`tainted-fund-flow` reasons at *input-slot* granularity: a guard is "a check
derived from the same `ApplicationArgs` slot". That is too coarse when a contract
packs several logical fields into one argument and validates only some of them.

```teal
txna ApplicationArgs 0
int 0
extract_uint16        ; read arg[0:2] ...
int 1
==
assert                ; ... and validate it (a selector / length / discriminator)

itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
extract 2 32          ; arg[2:34] -- an embedded address, NEVER checked
itxn_field Receiver   ; <-- attacker steers the payment with the unvalidated bytes
itxn_submit
```

The slot-granular detector sees "the argument was checked" and suppresses the
finding — a **false negative**. This detector closes the gap.

## How

It runs the **byte-interval taint** engine
(`tealtools.dataflow.byte_taint`, `validate=True`), which tracks taint per
byte-offset and lets an `assert(slice == const)` clear only the exact bytes it
pins. A payment sink whose value still carries tainted (un-validated) bytes after
narrowing is attacker-controlled at the byte level.

To stay precise and non-overlapping it reports only the **net-new** findings:
it runs `tainted-fund-flow` first and subtracts whatever that already flags (the
plain whole-value cases it owns). What remains is exactly the partial-validation
class. Sender/creator-gated sinks are suppressed (shared `security.common`
machinery), and a sink whose flowing bytes *are* validated is cleared by the
narrowing, so it never reaches here.

## Relationship to the type-recovery work

The tainted byte window is the same wire-format reasoning the ARC4 encoded-type
recovery uses: a contiguous 32-byte tainted window is reported as
"address-sized", the byte-offset analogue of recovering `arc4.Address` at that
offset. This is the byte-interval taint engine's first wiring into a live
detector.

## Severity

Inherits the sink field's severity (`Receiver`/`AssetReceiver` HIGH,
`Amount`/`AssetAmount` MEDIUM).
