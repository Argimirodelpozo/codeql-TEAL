# arbitrary-inner-asset

Reports attacker-controlled `XferAsset` selectors that can move an arbitrary ASA
from the application. A selector is suppressed when the same lifted inner
transaction returns the asset to a receiver derived from `txn Sender`.

Both taint/guard reasoning and inner-transaction correlation run on lifted
pre-IR. There is no representation-prefixed alias or weaker SSA fallback.

## How to fix

Pin the caller-supplied asset id to the ASA the app manages (an enforced `==`
against a constant), gate the transfer on `txn Sender` equal to a trusted
identity, or send the asset back to the caller (`AssetReceiver` derived from
`txn Sender` — a withdraw of the caller's own choice is not a confused deputy).
`!= 0` / `> 0` checks and comparisons between two caller inputs are not
credited.

<!-- verify: arbitrary-inner-asset clean -->
```teal
#pragma version 10
// pin the selector to the ASA this app manages
txna ApplicationArgs 1
btoi
int 31566704
==
assert
itxn_begin
int axfer
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field XferAsset
global CreatorAddress
itxn_field AssetReceiver
int 1000
itxn_field AssetAmount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

<!-- verify: arbitrary-inner-asset finding -->
```teal
#pragma version 10
// VULNERABLE: the caller names which ASA leaves the app; it goes to the creator
itxn_begin
int axfer
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field XferAsset
global CreatorAddress
itxn_field AssetReceiver
int 1000
itxn_field AssetAmount
int 0
itxn_field Fee
itxn_submit
int 1
return
```

```python
assert asset == Asset(31566704)
```

Suppress an intended finding with `// tealql-ignore: arbitrary-inner-asset` on
the `itxn_field XferAsset` line (or the line above), or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The return-to-sender suppression is per inner transaction: it
applies only when the SAME lifted inner transaction's `AssetReceiver` derives
from `txn Sender`. Likewise an inner OPT-IN — every `AssetReceiver` is `global
CurrentApplicationAddress`, every `AssetAmount` the constant 0 (or unset), no
`AssetCloseTo` / `AssetSender` — moves nothing out and is not reported.
