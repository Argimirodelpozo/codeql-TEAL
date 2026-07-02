# Attacker-Controlled State-Write Key

**Severity:** critical–medium (graded per sink op) · **Applies to:** application

## What it looks for

A user-input-tainted value reaching the KEY (the destination slot) of a persistent state write — `app_global_put` / `app_local_put` / `box_put` / `box_create` / `box_replace` — lets the attacker write to a slot they choose: overwrite the contract's own owner / admin / accounting GLOBAL state, or collide with a sensitive box. Only the KEY is flagged, not the VALUE (storing user data is normal). Findings are graded per sink op: `app_global_put` is `critical`, `app_local_put` / `box_put` / `box_replace` are `high`, `box_create` is `medium`.

## How it works

Runs on the lifted Puya IR via the `common.ir_lifter` bridge, over the state-write sinks (`fund_flow.tainted_state_writes`). The taint is interprocedural (across `callsub`, frame-resolved) and guard dominance is computed within the lifted subroutine. A finding is emitted only when the tainted KEY reaches the sink UNGUARDED — no dominating check of the key or of `txn Sender`.

Low-FP by construction: a key from `txn Sender` (the `box[Sender]` per-caller pattern) is not a taint source, and a key checked against state is guard-cleared. This is a new sink CATEGORY — the first IR detector on a non-itxn sink — with no SSA sibling; lift-only, so a contract that doesn't lift is simply not analysed by this detector.

## Examples

Vulnerable — the detector flags this (the attacker chooses the GLOBAL key from `ApplicationArgs 0`, so they can overwrite any slot including owner/admin):

```teal
#pragma version 10
    txna ApplicationArgs 0
    txna ApplicationArgs 1
    app_global_put
    int 1
    return
```

Safe — the detector stays quiet (the key is `txn Sender`, a per-caller slot, not attacker-chosen and not a taint source):

```teal
#pragma version 10
    txn Sender
    txna ApplicationArgs 0
    app_global_put
    int 1
    return
```

## Files

- `ir_tainted_state_write.py` — the detector (extends `security._ir_taint_sink._IrTaintSinkDetector`, overriding `_raw_findings` to use the state-write flow function).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus (`global_arbitrary_key`, `box_arbitrary_key`, `checked_key`, `constant_key`, `sender_keyed`) — live under `tests/benchmark/ir-tainted-state-write/`.
