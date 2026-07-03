# unsafe-division-order

**Precision loss from divide-before-multiply.**

AVM integer division truncates toward zero. Computing `(a / b) * c` discards the
remainder of `a / b` *before* scaling by `c`, losing up to `c - 1` units versus the
mathematically-equal `(a * c) / b`, which truncates only once, at the very end:

```teal
txna ApplicationArgs 0   ; a
btoi
txna ApplicationArgs 1   ; b
btoi
/                        ; a / b   <-- truncates here, remainder lost
txna ApplicationArgs 2   ; c
btoi
*                        ; (a / b) * c
```

In share-price / exchange-rate / reward-distribution math this is a systematic
value leak — rounding always favours one side — and it is among the most common
arithmetic bugs auditors find in DeFi contracts.

## How it decides

A def-use shape match on the SSA: a multiply (`*` / `b*`) one of whose operands is
produced *directly* by a divide (`/` / `b/` / `divw`). That is the
divide-before-multiply order; the fix is to multiply first, `(a * c) / b`. A divide
by the literal `1` (never truncates) is excluded.

## Scope

A correctness/precision smell, not an exploit primitive — reported at **MEDIUM**
and intended as a "review this expression" signal. Floor-then-scale is occasionally
intentional, so the finding points the auditor straight at the divide and the
multiply to confirm. Applies to both apps and logic sigs (arithmetic is
kind-agnostic).
