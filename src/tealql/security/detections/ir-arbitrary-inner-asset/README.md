# Attacker-Controlled Inner Asset-Transfer Target

**Severity:** high · **Applies to:** application

## What it looks for

A user-input-tainted `XferAsset` — *which* ASA moves out of the app's holdings — lets the attacker pick the asset, draining a balance the contract didn't mean to touch.

## How it works

Same taint-to-sink shape as [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), but on the `XferAsset` field. It runs on the lifted Puya IR via the `common.ir_lifter` bridge, inheriting the IR layer's across-`callsub` guard dominance and cross-contract caller-pinned suppression. A finding is emitted only when the tainted asset selector reaches the sink UNGUARDED — no dominating check of the value or of `txn Sender`.

Plus an asset-specific RECEIVER-CONTEXT suppression: if the asset returns to the caller — the inner txn's `AssetReceiver` flows from the sender / the app itself — the chooser is only moving an asset to themselves, not a third-party drain, so it is not a finding. That suppression is computed on the SSA `prog` (reusing the shared sender-flow helper) and correlated by `XferAsset` source line. It supersedes the SSA `arbitrary-inner-asset` and falls back to it when a contract doesn't lift.

## Examples

Vulnerable — the detector flags this. The attacker names the asset (`ApplicationArgs 1`) AND it goes to a third party (`Accounts 1`):

```teal
#pragma version 10
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field XferAsset
    txna ApplicationArgs 2
    btoi
    itxn_field AssetAmount
    txn Accounts 1
    itxn_field AssetReceiver
    itxn_submit
    int 1
    return
```

Safe — the detector stays quiet. The attacker still names the asset, but it returns to `txn Sender` (the caller), so it isn't a third-party drain:

```teal
#pragma version 10
    itxn_begin
    int axfer
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field XferAsset
    txn Sender
    itxn_field AssetReceiver
    txna ApplicationArgs 2
    btoi
    itxn_field AssetAmount
    itxn_submit
    int 1
    return
```

## Files

- `ir_arbitrary_inner_asset.py` — the detector (extends `tealql.security._ir_taint_sink._IrTaintSinkDetector`, adding the receiver-context `_suppress` post-filter).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus, including a `pinned_asset` and the `withdraw_to_self` receiver-context case — live under `tests/benchmark/ir-arbitrary-inner-asset/`.
