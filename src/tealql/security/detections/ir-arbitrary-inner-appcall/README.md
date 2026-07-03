# Attacker-Controlled Inner-Transaction App-Call Target

**Severity:** high · **Applies to:** application

## What it looks for

A user-input-tainted value reaching an inner transaction's `ApplicationID` lets the attacker pick WHICH application the contract calls. The contract will call any application the attacker names, so an attacker can route the app's inner call — and whatever authority it carries — into a malicious target.

## How it works

Same taint-to-sink shape as [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md), but on the `ApplicationID` field. It runs on the lifted Puya IR via the `common.ir_lifter` bridge, so it inherits the IR layer's across-`callsub` guard dominance, validation-subroutine guards, typed reasoning, and cross-contract caller-pinned suppression. A finding is emitted only when the tainted target reaches the sink UNGUARDED — no dominating check of the target value or of `txn Sender` — and is not derived from a trusted/pinned argument.

It supersedes the SSA `arbitrary-inner-appcall` and falls back to it when a contract doesn't lift.

## Examples

Vulnerable — the detector flags this (`ApplicationID` is decoded straight from `ApplicationArgs 1`, unchecked):

```teal
#pragma version 10
    itxn_begin
    int appl
    itxn_field TypeEnum
    txna ApplicationArgs 1
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
```

Safe — the detector stays quiet (`ApplicationID` is a hard-coded constant, not attacker-controlled):

```teal
#pragma version 10
    itxn_begin
    int appl
    itxn_field TypeEnum
    int 12345
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
```

## Files

- `ir_arbitrary_inner_appcall.py` — the detector (a thin config over the shared `tealql.security._ir_taint_sink._IrTaintSinkDetector` base).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus, including a `pinned_target`, a `sender_gated` case, and a `proxy_forwarder` case (selector checked, target app id not) — live under `tests/benchmark/ir-arbitrary-inner-appcall/`.
