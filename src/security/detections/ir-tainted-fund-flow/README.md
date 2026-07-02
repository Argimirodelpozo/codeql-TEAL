# Attacker-Controlled Inner-Transaction Fund Flow

**Severity:** critical–medium (graded per field) · **Applies to:** application

## What it looks for

An attacker-controlled value reaching a fund-flow inner-transaction field — `Receiver` / `AssetReceiver` / `Amount` / `AssetAmount` / `CloseRemainderTo` / `AssetCloseTo` — without a dominating guard lets the attacker redirect, size, or sweep a payment. Findings are graded per sink field: `CloseRemainderTo` / `AssetCloseTo` (account drain) are `critical`, `Receiver` / `AssetReceiver` are `high`, `Amount` / `AssetAmount` are `medium`.

This is the **primary** fund-flow detector, and the anchor of the IR taint-to-sink family (arbitrary-inner-appcall/asset, tainted-fee/freeze/asset-admin/log/state-write all share its engine).

## How it works

Runs on the lifted Puya IR via the `common.ir_lifter` bridge, so the taint analysis is interprocedural: it follows attacker input across `callsub` boundaries and resolves subroutine frame parameters, and it computes guard dominance *within* the lifted subroutine. A finding is emitted only for a value that reaches the sink UNGUARDED — no dominating check of the value or of `txn Sender` — and that is not derived from a trusted/pinned argument (`param_derived`).

The key edge over the SSA `tainted-fund-flow` is **guard dominance across a `callsub`**: `PathPredicateAnalysis` is context-INSENSITIVE there, so an owner/sender check placed before a callsub on the path to the sink is lost at the multi-caller return merge (a false positive the IR clears). It also inherits validation-subroutine guards, typed reasoning, and cross-contract caller-pinned suppression. When a contract doesn't lift (~0.1% of mainnet) the detector defers to its SSA sibling `tainted-fund-flow`, so it is the single complete entry point; the SSA detector is `superseded_by` this one and skipped in default scans.

## Examples

Vulnerable — the detector flags this (`Receiver` comes straight from `ApplicationArgs 0`, unchecked):

```teal
#pragma version 10
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
```

Safe — the detector stays quiet (a `Sender == CreatorAddress` check dominates the sink):

```teal
#pragma version 10
    txn Sender
    global CreatorAddress
    ==
    assert
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    itxn_submit
    int 1
    return
```

## Files

- `ir_tainted_fund_flow.py` — the detector (a thin config over the shared `security._ir_taint_sink._IrTaintSinkDetector` base).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus, including an `owner_guard_across_callsub` and a `validation_sub_guard` case — live under `tests/benchmark/ir-tainted-fund-flow/`.
