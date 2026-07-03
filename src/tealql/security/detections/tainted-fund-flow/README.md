# Attacker-Controlled Inner-Transaction Fund Flow (SSA)

**Severity:** high–medium (graded per field) · **Applies to:** application

## What it looks for

A user-input-tainted value reaching an inner-transaction `Receiver` / `AssetReceiver` / `Amount` / `AssetAmount` that is NOT dominated by a check of that value or the transaction `Sender` — the attacker can redirect a payment or control how much moves. (`RekeyTo` / `CloseRemainderTo` / `AssetCloseTo` have their own dedicated validators; this detector covers the payment fields they don't, and adds the user-input precondition those taint-free validators lack.) Findings are graded per sink field: `Receiver` / `AssetReceiver` are `high`, `Amount` / `AssetAmount` are `medium`.

## How it works

This is the SSA-layer detector. It reuses the existing machinery rather than a parallel engine: `common.inner_txn_field_assigns` (sinks), a forward user-input taint over the PySSA def-use / phi / scratch relation (precondition + value-check), and `PathPredicateAnalysis` (guard dominance). Because taint propagates through all ops, a guard like `arg < 100` is automatically tainted by the same input slot, so the value-check is just a taint-slot overlap; the sender-check reuses `common._operand_flows_from_field_var` (Sender is a direct read).

Guard dominance is interprocedural for free (`PathPredicateAnalysis` propagates caller predicates across `callsub` edges), and so is the taint: the base SSA def-use relation leaves `frame_dig` disconnected, but `_user_input_taint` unions each `frame_dig` param read's taint from the caller args bound to it (`tealql.tealtools.passes.frame_flow.frame_param_sources`), so a value fed into a subroutine parameter and paid out inside the callee is caught natively — no IR lift, no per-detector supplement.

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

## Note

Superseded by the IR-layer [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), which matches or beats this detector on every analysis axis (across-`callsub` dominance, validation-subroutine guards, typed reasoning, cross-contract caller-pinned suppression) and falls back to *this* detector when a contract doesn't lift. This detector declares `superseded_by = "ir-tainted-fund-flow"`; it stays registered (for the benchmark, that fallback, and standalone use) but is skipped in default scans so the IR detector is the single fund-flow entry point. Ask for it explicitly (`only: [tainted-fund-flow]`) to override.

## Files

- `tainted_fund_flow.py` — the detector.

Test fixtures — a `vuln` / `safe` precision-and-recall corpus — live under `tests/benchmark/tainted-fund-flow/`.
