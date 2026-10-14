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

## How to fix

Multiply before dividing, so the result truncates once: `(a * c) / b`. Prove
the intermediate product fits in uint64, or use `mulw` + `divmodw` for a
128-bit intermediate (neither is matched by this detector).

<!-- verify: unsafe-division-order clean -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
byte "rate"
app_global_get
*
byte "total"
app_global_get
/
itob
log
int 1
return
```

<!-- verify: unsafe-division-order finding -->
```teal
#pragma version 10
txna ApplicationArgs 0
btoi
byte "total"
app_global_get
/
byte "rate"
app_global_get
*
itob
log
int 1
return
```

```python
out = amount * rate // total      # not amount // total * rate
```

When floor-then-scale is intended (rounding down to a lot size,
`(x / unit) * unit`), suppress with `// tealql-ignore: unsafe-division-order`
on the flagged multiply line or the line above, or record it in a baseline
(`--update-baseline` / `--baseline PATH`).

## False positives

- Intentional floor-then-scale (lot-size rounding, `(x / unit) * unit`) is
  reported by design.
- MAY semantics: a multiply operand reached through a phi or a scratch
  round-trip is flagged if ANY arm/store is a divide, even when the dividing
  path is not the one taken.

## Scope

A correctness/precision smell, not an exploit primitive — reported at **MEDIUM**
and intended as a "review this expression" signal. Floor-then-scale is occasionally
intentional, so the finding points the auditor straight at the divide and the
multiply to confirm. Applies to both apps and logic sigs (arithmetic is
kind-agnostic).
