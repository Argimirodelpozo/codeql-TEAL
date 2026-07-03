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
  `common._operand_flows_from_field_var`, so a pin behind a subroutine or a
  scratch slot still counts (verified).
- A dynamic-index `gtxns*` read (sibling index on the stack, not statically known)
  is skipped — soundly, no false positive.

## Severity

`HIGH` — crediting funds the app never received is a direct theft primitive.
