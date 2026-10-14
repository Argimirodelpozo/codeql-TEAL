# tainted-log

Reports unguarded attacker-controlled data emitted through `log`, where callers
or off-chain indexers may treat it as trusted output. Evaluated on lifted pre-IR.

## How to fix

Log only values the contract has validated or computed: bound or pin every
attacker-controlled component of the logged bytes (constant pin, constant set,
ordering bound against a constant), or gate the log behind a sender pin
(`txn Sender == global CreatorAddress`). Every tainted leaf of the logged
value must be covered: checking one component of a `concat` leaves the other
reported.

<!-- verify: tainted-log clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
dup
int 100
<=
assert
byte "deposit:"
swap
itob
concat
log
int 1
return
```

<!-- verify: tainted-log finding -->
```teal
#pragma version 10
byte "deposit:"
txna ApplicationArgs 0
concat
log
int 1
return
```

```python
assert amount <= 100
log(b"deposit:" + op.itob(amount))
```

Echoing caller input is often intended (ARC-4 return values, event logs that
indexers treat as untrusted). Suppress with `// tealql-ignore: tainted-log` on
the flagged `log` line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

Any `log` of unchecked input is reported, including ARC-4 return values and
events whose consumers already treat the data as caller-supplied; severity is
LOW for that reason. Same engine conservatism as `tainted-fund-flow`.
