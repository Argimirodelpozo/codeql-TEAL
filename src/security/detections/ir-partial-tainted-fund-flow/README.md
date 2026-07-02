# Partially-Validated Attacker-Controlled Fund Flow

**Severity:** high–medium (graded per field) · **Applies to:** application

## What it looks for

A contract that packs several logical fields into ONE argument and validates only some of them — checking `arg[0..2]` while an embedded address at `arg[2..34]` steers `Receiver` — leaves the boolean fund-flow detector a false negative, because that detector reasons about guards at input-SLOT granularity. This detector closes the partial-validation blind spot at BYTE granularity, on the `Receiver` / `AssetReceiver` / `Amount` / `AssetAmount` payment fields (graded `high` for the receiver fields, `medium` for the amount fields).

It is the byte-precise complement to [`ir-tainted-fund-flow`](../ir-tainted-fund-flow/README.md): that detector owns the whole-value cases, and this one reports only the NET-NEW partial-validation findings the boolean detector cannot see.

## How it works

Runs on the lifted Puya IR via the `common.ir_lifter` bridge, so it gets the IR's across-`callsub` guard dominance and interprocedural frame-resolved taint. `byte_taint_view` carries the SSA byte-interval taint (with `validate=True` — an `assert(slice == clean)` guard clears exactly the bytes it pins) up onto the IR registers. A register that still holds un-validated attacker bytes drives a synthetic boolean taint map into the IR fund-flow engine with `sender_only=True`: byte-taint already owns input-validation at byte precision, so only sender/creator guards suppress — an input-slot guard would reproduce the very blind spot (one sub-field's check spuriously guarding another).

It then subtracts the whole-value cases owned by `ir-tainted-fund-flow` and reports the remainder. When a contract doesn't lift, the detector defers to its SSA sibling `partial-tainted-fund-flow`.

## Examples

Vulnerable — the detector flags this. Only a 2-byte selector prefix (`arg[0..2]`) is validated; the 32-byte address at `arg[2..34]` that becomes `Receiver` is never checked:

```teal
#pragma version 10
    txna ApplicationArgs 0
    int 0
    extract_uint16
    int 1
    ==
    assert
    itxn_begin
    int pay
    itxn_field TypeEnum
    txna ApplicationArgs 0
    extract 2 32
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
```

Safe — the detector stays quiet. The exact bytes that steer `Receiver` (`arg[2..34]`) are validated against a known address:

```teal
#pragma version 10
    txna ApplicationArgs 0
    extract 2 32
    addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5HFFY
    ==
    assert
    itxn_begin
    int pay
    itxn_field TypeEnum
    txna ApplicationArgs 0
    extract 2 32
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
```

## Files

- `ir_partial_tainted_fund_flow.py` — the detector (extends `security._ir_taint_sink._IrTaintSinkDetector`, overriding the taint view and raw-findings hooks for byte-precise taint).

Test fixtures — a `vuln` / `safe` precision-and-recall corpus, including `selector_validated_address_unchecked`, `abi_tuple_recipient`, and a `whole_value_owned_by_tff` net-new-suppression case — live under `tests/benchmark/ir-partial-tainted-fund-flow/`.
