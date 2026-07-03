# arbitrary-inner-appcall

**Attacker-controlled inner-application-call target.**

A user-input-tainted value reaching an inner transaction's `ApplicationID` — the
application this contract *calls* — with no dominating check of that value or of
`txn Sender`. The contract becomes a **confused deputy**: whatever authority it
holds (its balance, its assets, admin rights it has over other apps) is exercised
on behalf of whoever names the app to call.

```teal
itxn_begin
int appl
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field ApplicationID    ; <-- attacker picks the callee
itxn_submit
```

## Why a separate detector from tainted-fund-flow

`tainted-fund-flow` owns the *payment* fields (`Receiver` / `AssetReceiver` /
`Amount` / `AssetAmount`) — "the money moved somewhere the attacker chose". This
detector owns the *call target* (`ApplicationID`) — "the contract acted *as a
program* the attacker chose". Different vulnerability, different remediation, so
they are reported distinctly. The two never double-report (disjoint field sets).

## How it decides

Reuses the shared machinery in `tealql.security.common`:

- `user_input_taint` — forward taint from `ApplicationArgs` / LogicSig args /
  `itxn LastLog`, interprocedural via the frame-flow bridge (a target fed into a
  proto parameter and called inside the callee is covered).
- `itxn_value_guarded` — a write is **safe** when a dominating predicate checks
  the same input slot (`ApplicationArgs[1] == <pinned>; assert`) or gates on
  `txn Sender` / `global CreatorAddress`.

A constant target, a target read from app state (not user-tainted), a pinned
target, and a sender-gated call are all silently accepted.

## Severity

`HIGH` — an unpinned call target is rarely legitimate; a real proxy still pins
the allowed callee set or gates on the caller.
