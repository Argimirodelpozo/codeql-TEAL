# partial-tainted-fund-flow

Reports the byte-granular validation bypass: one portion of an argument is
validated while different attacker-controlled bytes steer a payment.

SSA byte intervals are carried onto lifted registers through explicit provenance,
then the lifted guard engine handles the sink interprocedurally. Whole-value
findings owned by `tainted-fund-flow` are subtracted. There is one canonical
detector ID and no SSA fallback.

## How to fix

Either pin the caller (the same sender checks `tainted-fund-flow` credits:
`txn Sender == global CreatorAddress`, a constant, or authority-preserved own
state, dominating or post-dominating the sink, directly or via a helper/caller),
or validate the exact bytes that steer the payment: an
`assert(slice(X) == clean)` whose slice covers the bytes reaching the field and
whose other side is attacker-independent clears those bytes. Validating a
different part of the same argument (selector, length prefix, another tuple
field) clears nothing; input-slot checks are deliberately ignored here.

<!-- verify: partial-tainted-fund-flow clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
extract 2 32
global CreatorAddress
==
assert
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
extract 2 32
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
```

Vulnerable counterpart (only the 2-byte prefix is validated; bytes 2..34 pick the receiver):

<!-- verify: partial-tainted-fund-flow finding -->
```teal
#pragma version 10
txna ApplicationArgs 0
int 0
extract_uint16
int 1
==
assert
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
extract 2 32
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
```

```python
assert Txn.sender == Global.creator_address
# or validate the field that is paid, not a sibling field:
assert args.receiver.native == Global.creator_address
```

If intended, suppress with `// tealql-ignore: partial-tainted-fund-flow` on the
flagged `itxn_field` line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

- Only equality pins clear bytes. A range bound on the extracted bytes
  (`extract_uint64` at offset 2, then `<= 1000`) is not credited and the
  `Amount` sink is still reported; use a sender pin or suppress.
- Byte-interval clearing is global on the validated value and is applied only
  when the validating assert is sound for every use; any unknown offset or
  length falls back to whole-value taint (soundness over precision, see
  `tealtools/dataflow/byte_taint.py`).
