# arbitrary-inner-appcall

Reports attacker-controlled `itxn_field ApplicationID` values that are not
constrained by a dominating value or Sender guard.

The detector runs on lifted pre-IR, where call arguments, frame parameters,
returns, scratch flow, and guard dominance are represented explicitly. The
detector name describes policy rather than implementation; there is no parallel
SSA detector or `ir-` alias. If lifting fails, analysis is reported incomplete.

## How to fix

Constrain the target before `itxn_submit`: compare the caller-supplied app id
against the expected constant and enforce it on every path (`assert`, or a
branch to `err`), or gate the call on `txn Sender` equal to a trusted identity
(`global CreatorAddress`, or admin state only an authorised writer sets).
Not credited: `!= 0` / `> 0` / truthiness checks, a comparison between two
caller inputs, `txn Sender == <ApplicationArgs>`, `Sender != X`, and a
`gtxn N Sender` check.

<!-- verify: arbitrary-inner-appcall clean -->
```teal
#pragma version 10
// the target must be the one app this contract is meant to call
txna ApplicationArgs 1
btoi
int 999
==
assert
itxn_begin
int appl
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field ApplicationID
int 0
itxn_field Fee
itxn_submit
int 1
return
```

<!-- verify: arbitrary-inner-appcall finding -->
```teal
#pragma version 10
// VULNERABLE: `!= 0` excludes one value; every other app id is still callable
txna ApplicationArgs 1
btoi
int 0
!=
assert
itxn_begin
int appl
itxn_field TypeEnum
txna ApplicationArgs 1
btoi
itxn_field ApplicationID
int 0
itxn_field Fee
itxn_submit
int 1
return
```

```python
assert app == Application(999)  # or: assert Txn.sender == Global.creator_address
```

A deliberate proxy/forwarder is still reported; suppress with
`// tealql-ignore: arbitrary-inner-appcall` on the `itxn_field ApplicationID`
line (or the line above), or record it in a baseline (`--update-baseline` /
`--baseline PATH`).

## False positives

None documented. Taint is followed interprocedurally through frame params,
returns and scratch; app state is not a taint source, so a state-derived target
is not reported.
