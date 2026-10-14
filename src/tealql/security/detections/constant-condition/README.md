# constant-condition

Flags guards whose outcome the static integer-range layer proves is fixed at
compile time — so the guard looks protective but constrains nothing:

- **vacuous assert** — `assert(cond)` where `cond` is always non-zero
  (e.g. `assert(OnCompletion <= 6)` when OnCompletion is structurally in
  `[0, 5]`): never halts, enforces nothing.
- **unsatisfiable assert** — `assert(cond)` where `cond` is always zero:
  the program rejects on every path reaching it; code beyond is dead.
- **constant branch** — `bnz` / `bz` whose condition is a compile-time
  constant: one arm is unreachable.

This detector consumes immutable value/range facts: findings are driven by the
field-enum / count bounds, `*_get` exists flags, `*_params_get` value
bounds and op-output seeds. It does **not** run assert-refinement
for the condition being inspected — that would tighten operands using the very
asserts being checked, making every asserted comparison look vacuous. The
ranges here come from value *facts* only, so a flagged guard is genuinely
redundant given what the program structurally knows.

Sound: a condition is reported only when its operand ranges *prove* the
outcome (disjoint / fully-ordered intervals); any overlap yields no
finding, and compound `&&` / `||` conditions are not decomposed.

Implementation: [`constant_condition.py`](constant_condition.py).
Ground-truth corpus: `tests/benchmark/constant-condition/`.

## How to fix

Replace the constant guard with the check that was intended, or delete it. A vacuous assert usually bounds a value the AVM already bounds (OnCompletion is in `[0, 5]`, `GroupIndex` is `< 16`, `x % K` is `< K`) — tighten it to the real requirement (e.g. `OnCompletion <= OptIn`). An unsatisfiable assert or a constant branch is a logic bug: fix the comparison or remove the dead arm. A guard is clean as soon as the operand ranges overlap the comparison boundary.

<!-- verify: constant-condition clean -->
```teal
#pragma version 10
txn OnCompletion
int OptIn
<=
assert
int 1
return
```

Vulnerable counterpart — OnCompletion is never above 5, so `<= 6` enforces nothing:

<!-- verify: constant-condition finding -->
```teal
#pragma version 10
txn OnCompletion
int 6
<=
assert
int 1
return
```

```python
assert Txn.on_completion <= OnCompleteAction.OptIn  # not `<= 6`
```

A deliberately defensive assert (belt-and-braces `OnCompletion <= DeleteApplication`) is reported as vacuous; suppress it with `// tealql-ignore: constant-condition` on the flagged line or the line above it, or record it in a baseline (`--update-baseline` / `--baseline PATH`).

## False positives

None documented. The detector reports only when the operand ranges PROVE the outcome and skips pure-constant conditions (compiler folding), so every finding is genuinely constant given the program's value facts; what it over-reports is intent — a redundant-but-deliberate defensive check is still flagged. Compound `&&` / `||` conditions are not decomposed (missed, not over-reported).
