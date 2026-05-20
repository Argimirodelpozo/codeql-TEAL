# Inner Transaction Sets CloseRemainderTo / RekeyTo / AssetCloseTo

**Severity:** high · **Applies to:** application

## What it looks for

An application that emits an inner transaction (`itxn_submit`) which sets any of `CloseRemainderTo`, `RekeyTo`, or `AssetCloseTo` via `itxn_field`. These three fields drain or transfer signing authority — an application's account is much more attacker-controllable than a single-tx escrow, so any inner-tx setter of these fields is almost always a bug or a deliberate footgun.

The correct pattern is to omit the field entirely (it defaults to the zero address), not to set it.

## How it works

**Per-assignment finding** — every `itxn_field <FIELD>` opcode where `FIELD` is one of the three dangerous names is reported, regardless of the value being assigned. No path-sensitivity is applied: even an `itxn_field RekeyTo` guarded behind a `bz` that's never taken still flags. This is intentional — the false-positive cost is low because the correct pattern is to never write these fields.

## Files

- `innerTxnCloseRekey.ql` — CodeQL implementation. Walks `InnerTransactionField` nodes.
- `inner_txn_close_rekey.py` — Python port. Walks `prog.assignments` for `op == "itxn_field"` and matching immediates.
- `innerTxnCloseRekey.expected` — `.expected` baseline for the QL test.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-conditional-itxn.teal` (itxn under a guard — still flagged).
