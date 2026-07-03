# Attacker-Controlled Asset-Freeze Target

**Severity:** high–medium (graded per field) · **Applies to:** application

## What it looks for

An inner asset-freeze (`afrz`) transaction freezes a specific holder's units of an ASA. A user-input-tainted `FreezeAssetAccount` lets the attacker freeze ANY account they name — a targeted denial-of-service on a victim's holdings — and, with a tainted `FreezeAsset`, of any asset the app can freeze. Findings are graded per field: `FreezeAssetAccount` is `high`, `FreezeAsset` is `medium`.

## How it works

Same taint-to-sink shape as [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), over the two freeze fields. It runs on the lifted Puya IR via the `common.ir_lifter` bridge, so the taint is interprocedural (across `callsub`, frame-resolved) and guard dominance is computed within the lifted subroutine. A finding is emitted only when the tainted target reaches the sink UNGUARDED — no dominating check of the value or of `txn Sender`.

This is a new capability with no SSA sibling — lift-only; a contract that doesn't lift is simply not analysed by this detector.

## Examples

Vulnerable — the detector flags this (`FreezeAssetAccount` is set from `ApplicationArgs 0`, unchecked, so the attacker freezes any account they name):

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

Safe — the detector stays quiet (an admin check dominates the `afrz`, so the attacker-named target isn't attacker-reachable):

```teal
#pragma version 10
    txn Sender
    byte "admin"
    app_global_get
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

## Files

- `ir_tainted_freeze.py` — the detector (a thin config over the shared `tealql.security._ir_taint_sink._IrTaintSinkDetector` base).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus (`freeze_arbitrary_account`, `freeze_constant_account`, `freeze_sender_gated`) — live under `tests/benchmark/ir-tainted-freeze/`.
