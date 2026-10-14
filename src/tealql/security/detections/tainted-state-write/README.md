# tainted-state-write

Reports attacker-controlled keys of global/local state and box mutations. The
value is deliberately not a sink: accepting user data is normal; letting users
choose an unguarded destination slot is the security issue. Evaluated on lifted
pre-IR.

## How to fix

Never let the caller choose the destination slot unchecked. Use constant keys,
keys derived from `txn Sender` (per-caller boxes are not a taint source), or
validate the key: pin it to a constant set (`k == "price" || k == "fee"`), an
equality against a constant or own state, or an ordering bound against a
constant on its numeric leaf. Alternatively gate the write with a sender pin
(`txn Sender == global CreatorAddress`). Existence predicates over the key
(`assert(box_get(k).exists)`, `app_opted_in`) also count. Every tainted leaf of
the key must be covered.

<!-- verify: tainted-state-write clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
byte "price"
==
txna ApplicationArgs 0
byte "fee"
==
||
assert
txna ApplicationArgs 0
txna ApplicationArgs 1
app_global_put
int 1
return
```

<!-- verify: tainted-state-write finding -->
```teal
#pragma version 10
txna ApplicationArgs 0
txna ApplicationArgs 1
app_global_put
int 1
return
```

```python
assert key == Bytes(b"price") or key == Bytes(b"fee")
```

If intended (an open key-value store), suppress with
`// tealql-ignore: tainted-state-write` on the flagged write line or the line
above, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The detector over-approximates the key as attacker-chosen
whenever any tainted leaf of it is unchecked (a key concatenated or hashed from
several arguments needs every component covered), and an operand the lift
cannot resolve is reported with source `unresolved`.
