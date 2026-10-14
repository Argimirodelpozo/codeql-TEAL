# unvalidated-group-sibling

**Trusting a sibling transfer the app never pins to itself.**

The most Algorand-native composition bug. A stateful app relies on a *sibling*
transaction in the same atomic group — "transaction 0 is a payment to me" — and
reads its value:

```teal
txna ApplicationArgs 0
byte 0xa1b2c3d4
==
assert
gtxn 0 Amount        ; trust an incoming payment of this size ...
int 1000000
>=
assert
txn Sender
gtxn 0 Amount
app_global_put       ; ... and credit the caller for it
```

The bug: it never asserts `gtxn 0 Receiver == Global.CurrentApplicationAddress`.
The attacker submits a group whose transaction 0 pays *someone else* — the app
credits them for funds it never received.

## Versus group-size-check

`group-size-check` validates the **count** of transactions in the group (so the
group can't be padded). This validates that a sibling the app draws **value** from
actually pays the app. Orthogonal — both can fire on the same contract.

## How it decides

For each immediate-index sibling read of a value field (`Amount` → payment,
`AssetAmount` → asset transfer), it requires a matching **receiver pin**: an
equality comparing that sibling's `Receiver` / `AssetReceiver` against
`global CurrentApplicationAddress` whose result reaches enforcement (`assert` or a
branch-to-reject). Missing pin → finding.

- The flow check is the shared phi / scratch / proto-frame-aware
  `_value_flow._operand_flows_from_field_var`, so a pin behind a subroutine or a
  scratch slot still counts (verified).
- A dynamic-index `gtxns*` read (sibling index on the stack, not statically known)
  is skipped — soundly, no false positive.

## How to fix

Before crediting a sibling's `Amount` / `AssetAmount`, assert that the same
sibling's `Receiver` / `AssetReceiver` equals `global CurrentApplicationAddress`
on every path from the read to an approving exit (an `assert`, or a branch whose
failing edge rejects). Also credited as pin targets: `global CreatorAddress`, an
address literal, and app state whose every writer is under an established
authority (a creator-only setter). A receiver pinned to state the CALLER can
write — their own local state, a slot written from `txn Sender` or
`ApplicationArgs` on an unguarded path, a foreign app's state — is NOT credited,
nor is a pin to `ApplicationArgs` / `txn Sender`. A pin on one router arm does
not cover a read on another.

<!-- verify: unvalidated-group-sibling clean -->
```teal
#pragma version 10
// deposit: credit the caller for gtxn 0 only once it is proven to pay THIS app
gtxn 0 TypeEnum
int pay
==
assert
gtxn 0 Receiver
global CurrentApplicationAddress
==
assert
txn Sender
byte "credit"
gtxn 0 Amount
app_local_put
int 1
return
```

<!-- verify: unvalidated-group-sibling finding -->
```teal
#pragma version 10
// VULNERABLE: gtxn 0 may pay anyone; the caller is still credited
gtxn 0 TypeEnum
int pay
==
assert
txn Sender
byte "credit"
gtxn 0 Amount
app_local_put
int 1
return
```

```python
assert pay.receiver == Global.current_application_address  # pay: gtxn.PaymentTransaction
```

If the sibling is deliberately allowed to pay elsewhere, suppress with
`// tealql-ignore: unvalidated-group-sibling` on the flagged `gtxn N Amount`
read (or the line above), or record the finding in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

- A sibling whose SENDER is pinned to the app / a stored escrow is an outflow,
  not a credit, but is still judged (`sibling-is-outflow-from-escrow`).
- Fixed 2026-10-10: a receiver pinned to state written under a creator-SIGNED
  sibling (`gtxn 1 Sender == <signing principal>`), and a receiver pinned to
  `app_params_get AppAddress` of an authority-preserved app id.
- Programs with legacy (non-`proto`) subroutines fall back to a whole-program
  existence check (a pin anywhere covers every read), which errs towards
  silence, not findings. Dynamic-index `gtxns` reads are skipped (no finding).

## Severity

`HIGH` — crediting funds the app never received is a direct theft primitive.
