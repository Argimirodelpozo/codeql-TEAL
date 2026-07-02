# Attacker-Controlled Inner-Transaction Fee

**Severity:** medium · **Applies to:** application

## What it looks for

A user-input-tainted `itxn_field Fee` lets the attacker choose the fee the app pays on an inner transaction — set it large and drain the app's algo balance one inflated inner txn at a time.

This is distinct from the `inner-txn-fee` detector, which flags a CONSTANT non-zero fee and explicitly skips dynamic ones; this covers exactly that skipped attacker-controlled case.

## How it works

Same taint-to-sink shape as [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), on the `Fee` field. It runs on the lifted Puya IR via the `common.ir_lifter` bridge, so the taint is interprocedural (across `callsub`, frame-resolved) and guard dominance is computed within the lifted subroutine. A finding is emitted only when the tainted fee reaches the sink UNGUARDED — no dominating check of the value.

This is a new capability with no SSA sibling — lift-only; a contract that doesn't lift is simply not analysed by this detector.

## Examples

Vulnerable — the detector flags this (`Fee` is decoded straight from `ApplicationArgs 0`, unchecked):

```teal
#pragma version 10
    itxn_begin
    int pay
    itxn_field TypeEnum
    global CurrentApplicationAddress
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

Safe — the detector stays quiet (the fee is bounded by a dominating check before the sink):

```teal
#pragma version 10
    txna ApplicationArgs 0
    btoi
    int 1000
    <=
    assert
    itxn_begin
    int pay
    itxn_field TypeEnum
    global CurrentApplicationAddress
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

A zero fee (`int 0; itxn_field Fee`, the pool-covered case) is likewise not flagged.

## Files

- `ir_tainted_fee.py` — the detector (a thin config over the shared `security._ir_taint_sink._IrTaintSinkDetector` base).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus (`attacker_fee`, `checked_fee`, `zero_fee`) — live under `tests/benchmark/ir-tainted-fee/`.
