# Attacker-Controlled Logged Data

**Severity:** low · **Applies to:** application

## What it looks for

A contract that `log`s a user-input-tainted value emits FORGED data to anything that trusts its logs: a CALLER reading its `LastLog` after an inner appcall — which is itself a taint source (`ItxnLastLog`), so a spoofed ARC-4 return value or event can make the caller act on attacker-chosen data — and off-chain indexers / dapps that treat the contract's logged events as truth. It is output-integrity rather than direct fund loss, hence `low` severity, but it is the on-chain SOURCE of the cross-contract `ItxnLastLog` taint the caller-side detectors react to.

## How it works

Runs on the lifted Puya IR via the `common.ir_lifter` bridge, over the `log` sink (`fund_flow.tainted_logs`). The taint is interprocedural (across `callsub`, frame-resolved) and guard dominance is computed within the lifted subroutine; the guard machinery clears a logged value that was validated first. A finding is emitted only when the tainted value reaches `log` UNGUARDED — no dominating check of the value.

This is a new capability with no SSA sibling — lift-only; a contract that doesn't lift is simply not analysed by this detector.

## Examples

Vulnerable — the detector flags this (attacker-controlled `ApplicationArgs 0` is logged verbatim):

```teal
#pragma version 10
    txna ApplicationArgs 0
    log
    int 1
    return
```

Safe — the detector stays quiet (the logged value is validated against a known constant first):

```teal
#pragma version 10
    txna ApplicationArgs 0
    byte 0x6f6b
    ==
    assert
    txna ApplicationArgs 0
    log
    int 1
    return
```

## Files

- `ir_tainted_log.py` — the detector (extends `tealql.security._ir_taint_sink._IrTaintSinkDetector`, overriding `_raw_findings` to use the `log` flow function).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus (`unguarded_log`, `param_fed_log`, `checked_log`, `constant_log`, `sender_log`) — live under `tests/benchmark/ir-tainted-log/`.
