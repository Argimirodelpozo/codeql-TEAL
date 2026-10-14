# tainted-fee

Reports attacker-controlled inner-transaction fees. This complements
`inner-txn-fee`, which checks statically known non-zero fees. Evaluated on lifted
pre-IR.

## How to fix

Set the inner fee to `0` (pooled from the outer transaction) or a constant, or
bound the attacker-supplied fee by a constant before use. A dominating
sender pin (`txn Sender == global CreatorAddress`) also clears the finding.
`> 0` / `!= 0` / a bare assert is not a bound.

<!-- verify: tainted-fee clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
int 2000
<=
assert
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 0
itxn_field Amount
txna ApplicationArgs 0
btoi
itxn_field Fee
itxn_submit
int 1
return
```

<!-- verify: tainted-fee finding -->
```teal
#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 0
itxn_field Amount
txna ApplicationArgs 0
btoi
itxn_field Fee
itxn_submit
int 1
return
```

```python
itxn.Payment(receiver=Txn.sender, amount=0, fee=0).submit()
```

If intended, suppress with `// tealql-ignore: tainted-fee` on the flagged
`itxn_field Fee` line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

None documented. Shares the lifted guard engine with `tainted-fund-flow`; a
fee bounded only against another attacker input, or by `> 0`, stays reported.
