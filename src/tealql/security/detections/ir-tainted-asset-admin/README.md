# Attacker-Controlled Asset Admin Role

**Severity:** critical–medium (graded per role field) · **Applies to:** application

## What it looks for

An inner asset-config (`acfg`) transaction sets an ASA's privileged roles. A user-input-tainted value reaching `ConfigAssetManager` (reconfigure / destroy), `ConfigAssetClawback` (claw back ANYONE's holdings), `ConfigAssetFreeze` (freeze any holder), or `ConfigAssetReserve` lets the attacker install THEMSELVES as that role — e.g. set clawback to their own address and then claw the asset out of every holder. Findings are graded per role: `ConfigAssetManager` / `ConfigAssetClawback` are `critical`, `ConfigAssetFreeze` is `high`, `ConfigAssetReserve` is `medium`.

## How it works

Same taint-to-sink shape as [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), over the four asset-config role fields. It runs on the lifted Puya IR via the `common.ir_lifter` bridge, so the taint is interprocedural (across `callsub`, frame-resolved) and guard dominance is computed within the lifted subroutine. A finding is emitted only when the tainted role value reaches the sink UNGUARDED — no dominating check of the value or of `txn Sender`.

This is a new capability with no SSA sibling — lift-only; a contract that doesn't lift is simply not analysed by this detector.

## Examples

Vulnerable — the detector flags this (the clawback address is set from `ApplicationArgs 0`, unchecked, so the attacker becomes the clawback of asset 100):

```teal
#pragma version 10
    itxn_begin
    int acfg
    itxn_field TypeEnum
    int 100
    itxn_field ConfigAsset
    txna ApplicationArgs 0
    itxn_field ConfigAssetClawback
    itxn_submit
    int 1
    return
```

Safe — the detector stays quiet (an owner check dominates the `acfg`, so the attacker-named clawback isn't attacker-reachable):

```teal
#pragma version 10
    txn Sender
    byte "owner"
    app_global_get
    ==
    assert
    itxn_begin
    int acfg
    itxn_field TypeEnum
    int 100
    itxn_field ConfigAsset
    txna ApplicationArgs 0
    itxn_field ConfigAssetClawback
    itxn_submit
    int 1
    return
```

## Files

- `ir_tainted_asset_admin.py` — the detector (a thin config over the shared `tealql.security._ir_taint_sink._IrTaintSinkDetector` base).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus, including `unguarded_manager`, `unguarded_clawback`, and a `sender_gated` case — live under `tests/benchmark/ir-tainted-asset-admin/`.
