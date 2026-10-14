# tainted-freeze

Reports attacker-controlled asset or account targets in inner freeze
transactions. Evaluated on lifted pre-IR.

## How to fix

Restrict who may freeze (a dominating `txn Sender == global CreatorAddress`,
constant, or authority-preserved own-state pin), or pin the target account /
asset to a value the attacker does not choose. Same credited guards as
`tainted-fund-flow`; `!= global ZeroAddress` or a length check is not a check.

<!-- verify: tainted-freeze clean -->
```teal
#pragma version 10
txn Sender
global CreatorAddress
==
assert
itxn_begin
int afrz
itxn_field TypeEnum
int 100
itxn_field FreezeAsset
txna ApplicationArgs 0
itxn_field FreezeAssetAccount
int 1
itxn_field FreezeAssetFrozen
itxn_submit
int 1
return
```

<!-- verify: tainted-freeze finding -->
```teal
#pragma version 10
itxn_begin
int afrz
itxn_field TypeEnum
int 100
itxn_field FreezeAsset
txna ApplicationArgs 0
itxn_field FreezeAssetAccount
int 1
itxn_field FreezeAssetFrozen
itxn_submit
int 1
return
```

```python
assert Txn.sender == Global.creator_address
```

If intended, suppress with `// tealql-ignore: tainted-freeze` on the flagged
`itxn_field` line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

None documented. Same engine conservatism as `tainted-fund-flow`
(`gtxn N Sender` authorisation not credited; unresolved operands reported).
