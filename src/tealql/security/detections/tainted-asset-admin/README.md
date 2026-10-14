# tainted-asset-admin

Reports attacker-controlled manager, clawback, freeze, or reserve roles in an
inner asset-configuration transaction. Evaluated on lifted pre-IR.

## How to fix

Do not take admin roles from caller input; when the app must set them, pin
the caller or the value. The lifted engine credits the same guards as
`tainted-fund-flow`: a dominating (or post-dominating) `txn Sender ==
global CreatorAddress` / constant / authority-preserved own-state pin, or a
value check pinning the role address (`== global CreatorAddress`, a constant,
own state whose writers preserve authority). `!= global ZeroAddress`, a length
check, or a comparison against another attacker input is not a check.

<!-- verify: tainted-asset-admin clean -->
```teal
#pragma version 10
txn Sender
global CreatorAddress
==
assert
itxn_begin
int acfg
itxn_field TypeEnum
txna Assets 0
itxn_field ConfigAsset
txna ApplicationArgs 1
itxn_field ConfigAssetManager
global CurrentApplicationAddress
itxn_field ConfigAssetClawback
itxn_submit
int 1
return
```

<!-- verify: tainted-asset-admin finding -->
```teal
#pragma version 10
itxn_begin
int acfg
itxn_field TypeEnum
txna Assets 0
itxn_field ConfigAsset
txna ApplicationArgs 1
itxn_field ConfigAssetManager
global CurrentApplicationAddress
itxn_field ConfigAssetClawback
itxn_submit
int 1
return
```

```python
assert Txn.sender == Global.creator_address
```

If intended (e.g. a factory deliberately handing roles to the caller-named
account), suppress with `// tealql-ignore: tainted-asset-admin` on the flagged
`itxn_field` line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

None documented. Shares the lifted guard engine with `tainted-fund-flow`, so
the same conservatism applies: authorisation through a group sibling
(`gtxn N Sender`) is not credited, and an unresolvable operand is reported
with source `unresolved`.
