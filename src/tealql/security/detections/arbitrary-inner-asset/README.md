# arbitrary-inner-asset

**Attacker-controlled inner asset-transfer target (asset confusion).**

The asset analogue of [arbitrary-inner-appcall](../arbitrary-inner-appcall/), and
the shape behind the **Tinyman** asset-confusion exploit ($3M, 2022 — a pool that
paid out the wrong asset). An inner asset transfer whose `XferAsset` — *which* ASA
moves out of the application account — is attacker-controlled, with no dominating
check and the asset not returned to the caller:

```teal
itxn_begin
int axfer
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field XferAsset      ; <-- attacker picks which asset leaves the app
addr <fixed/other>
itxn_field AssetReceiver  ; <-- ... sent somewhere they didn't deposit for
itxn_field AssetAmount
itxn_submit
```

The app moves whichever asset the attacker names out of its holdings — a confused
deputy over the app's asset balances.

## Versus tainted-fund-flow

`tainted-fund-flow` owns `AssetReceiver` / `AssetAmount` ("where / how much"). This
owns the asset **selector** `XferAsset` ("which asset") that it doesn't.

## Precision

The legitimate "withdraw the asset I name back **to myself**" pattern is suppressed:
if the same inner transaction's `AssetReceiver` flows from `txn Sender`, the chooser
only receives their own chosen asset, not a third party's. A value-pin on the asset
id or a `txn Sender` gate also suppresses (shared `common.itxn_value_guarded`). Only
the immediate inner-txn block (`itxn_begin` / `itxn_next` … `itxn_submit`) is
correlated for the receiver.

## Severity

`HIGH` — moving an attacker-chosen asset to a third party is a direct drain of the
app's holdings.
