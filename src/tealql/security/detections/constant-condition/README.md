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
