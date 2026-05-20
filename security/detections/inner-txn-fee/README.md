# Inner Transaction Non-Zero Fee

**Severity:** high · **Applies to:** application

## What it looks for

An application that emits an inner transaction explicitly setting `Fee` to a non-zero constant. The recommended pattern is fee 0 with the *caller* covering the fee pool — the application account doesn't get drained on repeated calls. Hardcoded non-zero fees in inner transactions are a common way to slowly drain the application's ALGO balance through attacker-triggered loops.

Dynamic (non-constant) fees aren't flagged. The detection deliberately only catches the static-non-zero case to match the QL form.

## How it works

**Per-assignment finding** — every `itxn_field Fee` whose source operand resolves to a `Const` with `int` kind and a non-zero value is reported. The constant-propagation pass must have run for the operand to be classified as a const-int; the Python port triggers it explicitly.

## Files

- `innerTxnFee.ql` — CodeQL implementation. Uses `innerTxnSetsNonZeroFee` from `SecGuideCommon.qll`.
- `inner_txn_fee.py` — Python port. Calls `prog.propagate_constants()` then walks for `itxn_field Fee` with a non-zero const-int operand.
- `innerTxnFee.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-dynamic-fee.teal` (dynamic fee — *not* flagged, kept to show the detector's blind spot).
