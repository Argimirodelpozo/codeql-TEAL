# tainted-fund-flow

Reports attacker-controlled values reaching inner-payment and asset-transfer
fund fields without a dominating value or Sender guard.

This is the canonical lifted pre-IR policy. Interprocedural parameters, returns,
validation helpers, post-dominating assertions, and scratch round trips are all
handled at that representation. The old SSA implementation and `ir-` alias were
removed; a failed lift produces an incomplete-analysis notification.

## How to fix

Gate the transfer with a check the lifted guard engine credits: either pin the
caller, or constrain EVERY attacker-controlled leaf of the sink value. One
dominating `assert` or branch-to-reject is enough; the check may also sit after
`itxn_submit` (post-dominating assert before the approving exit), in a
validation subroutine that asserts its parameter (bool-returning or returning
the parameter), or in every caller of the subroutine that holds the sink.

Sender checks that count:

- `txn Sender == global CreatorAddress`, or `txn Sender ==` a byte/`addr`
  constant (also `!=` that branches to `err`/reject);
- `txn Sender == app_global_get K` when every writer of `K` is itself
  authority-guarded (reported with an `[INCOMPLETE]` premise about `K`'s
  initial value);
- an `||` of such pins (every arm must pin).

Value checks that count (per tainted leaf):

- `==` against a value the attacker does not choose: a constant,
  `global CreatorAddress`, or own state whose writers preserve authority
  (address-typed pins);
- an ordering bound against such a value (`btoi(arg) <= 1000000`, `x >= 2`),
  or against a group sibling's `gtxn N Amount` (a bound that costs the
  attacker);
- membership in a constant set (`k == "a" || k == "b"`).

Not credited: `!= 0`, `> 0`, `>= 1`, a bare `assert(x)` (exclusions of one
value); `Receiver != global ZeroAddress`; `len(x) == 32` (bounds the length,
not the value); a comparison against another attacker input
(`Accounts[1] == Accounts[2]`, `btoi(arg0) <= btoi(arg1)`); `gtxn N Sender`
(the group composer chooses it); `Sender == <attacker arg>`; a pin inside only
one arm of an `||`, `select` or phi. A check must cover every tainted leaf:
`Amount = btoi(arg0) + btoi(arg1)` under `assert(btoi(arg0) <= 100)` is still
reported, because `arg1` is free.

<!-- verify: tainted-fund-flow clean -->
```teal
#pragma version 10
txn Sender
global CreatorAddress
==
assert
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
itxn_field Receiver
txna ApplicationArgs 1
btoi
itxn_field Amount
itxn_submit
int 1
return
```

<!-- verify: tainted-fund-flow clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
int 1000000
<=
assert
itxn_begin
int pay
itxn_field TypeEnum
global CreatorAddress
itxn_field Receiver
txna ApplicationArgs 0
btoi
itxn_field Amount
itxn_submit
int 1
return
```

Vulnerable counterpart (`> 0` is not a value check, the receiver is unchecked):

<!-- verify: tainted-fund-flow finding -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
int 0
>
assert
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 1
itxn_field Receiver
txna ApplicationArgs 0
btoi
itxn_field Amount
itxn_submit
int 1
return
```

```python
assert Txn.sender == Global.creator_address          # sender pin, or
assert amount <= UInt64(1_000_000)                   # bound every attacker leaf
```

If the flow is intended (e.g. a permissionless withdrawal of the caller's own
recorded balance the engine cannot see), suppress it with
`// tealql-ignore: tainted-fund-flow` on the flagged `itxn_field` line or the
line above, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

- Byte-granular cleanliness is invisible to this whole-value engine: a clean
  window cut out of an attacker buffer (`extract 0 32` of
  `concat(global CreatorAddress, arg)`) is still reported. That shape is
  `partial-tainted-fund-flow`'s domain
  (`tests/benchmark/partial-tainted-fund-flow/safe/clean_prefix_recipient.teal`).
- A sibling signer pinned to a stored address that is not a signing principal
  (e.g. a configured escrow) is deliberately not credited; `gtxn K Sender ==
  global CreatorAddress` and `global CallerApplicationID == <const>` are.
- An operand the lift cannot resolve is reported with source `unresolved`
  rather than assumed clean.
