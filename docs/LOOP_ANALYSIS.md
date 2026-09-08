# Loop induction, invariants and execution costs

Loop structure, semantic iteration limits and resource ceilings answer different
questions. The shared loop graph preserves matched call continuations and lists
reachable natural loops and irreducible regions. Numeric induction certificates
are independent of opcode credit; cost queries consume those certificates.

```python
from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.budget import analyze_loops, constant_trip_cap
from tealql.tealtools.budget.upper_cost import UpperCost

facts = program.facts(FactDomain.RANGES)
for loop in analyze_loops(program):
    proof = facts.loop_analysis().summary(loop)
    print(loop.semantic_trip_bound, proof.reason)
    print(loop.max_iterations)  # existing budget/stack execution ceiling

upper = UpperCost(program).from_block(program.entry_blocks()[0])
print(upper.upper, upper.reasons)
```

`constant_trip_cap` remains compatible with existing callers. Its result can now
come from a bounded runtime limit. The CLI's `loops --json` output adds
`semantic_trip_bound` and `semantic_reason`; it preserves `max_iterations` as
the established resource ceiling. A missing semantic bound is explicit.

## Supported induction

The proof records the initial interval, signed progress interval, tested limit,
comparison polarity, counter invariant, guard location and semantic trip cap.
All entry values and all backedges participate. A continuation guard must be
unavoidable on every lap; post-test forms additionally require the tested value
to be the actual backedge update.

Supported forms include:

- Increasing and decreasing stack and immediate-scratch counters.
- Strict and inclusive comparisons, both `bz` and `bnz` polarities.
- Pre-test and supported post-test loops, including their boundary iteration.
- Positive variable strides and different progress on different backedges.
- Runtime limits with numeric bounds at the test, including bounds carried
  unchanged through a loop after an assertion.
- Equality exits when the exact initial value and stride can reach the limit.
- Nested loops carrying an outer counter unchanged. Physical phi edges prove
  identity; equality of flattened source-value sets is insufficient.

For example, a zero-based counter with `i < n`, an established `n <= 10`, and
step one has a trip cap of ten and an exit interval contained in `[0, 10]`.
A scratch counter or a post-test counter running to ten now obtains the same
cap and exact exit value as the equivalent pre-test stack loop.

Scratch proofs inspect last writers at the named instruction. Writer-free
cycles preserve their incoming value; resets and modifying cycles cannot be
dropped. Dynamic stores and calls that could affect the slot retain a refusal.
No scratch aliases or canonical SSA operands are rewritten.

The cap bounds semantic laps, including the initial body execution of a
post-test loop. It does not promise normal termination: an inner loop, assertion,
arithmetic error or resource limit may stop an execution first. Addition and
subtraction use successful uint64 arithmetic, not wraparound. Equality and
progress checks do not treat arithmetic failure as a successful exit.

## Numeric fixed points

`range_at` also consumes bounded interval fixed points over cyclic SSA value
webs. Threshold widening uses numeric endpoints and guard thresholds, followed
by simultaneous narrowing. Only a checked post-fixpoint is returned. Every phi
arm participates, including resets; partial and unseeded phis remain unknown.

This supports useful invariants even when no progress proof exists. A loop that
starts at zero, runs while `i < 50`, and either resets to three or advances by
four has a header invariant `[0, 53]`. Repeated resets can prevent normal exit,
so that invariant does not produce a trip cap.

Copy/phi fixed points separately retain the bounds of every seed through pure
identity cycles. The induction checker uses a base interval query that does not
consume the certificate being constructed. Facts remain scoped to the current
program revision, and stale cached queries refuse after a mutation.

## Budget proof correction

The previous exhaustion filter compared a semantic trip cap with a ceiling
computed from the cheapest cycle and maximum possible pooled credit. That
comparison could discard a loop whose expensive path exceeded available credit.
The analogous claim that stack failure necessarily happened first had the same
problem. Neither comparison now suppresses a candidate.

Suppression requires a finite execution-cost upper bound and guaranteed credit:

- An unavoidable, sufficient `OpcodeBudget` guard; or
- An explicit `guaranteed_entry_credit` supplied to
  `find_budget_exhaustion_candidates`, covering every program-entry execution.

`BudgetContext.initial_credit` remains a ceiling and is not silently promoted
to a guarantee. A capped candidate reports its existing cap and the missing
cost/credit proof instead of requesting another ranking function.

`UpperCost` composes independently certified nested-loop visit counts and
matched calls. It charges alternative blocks conservatively, includes initial
and final partial laps and rejecting callee paths, and allows for the assembler's
two possible literal-table instructions. Recursive calls, uncovered cycles,
unknown opcode costs and exhausted proof budgets have no finite upper result.
A guard inside a callee cannot discharge its caller's remaining execution cost
without that continuation context.

The Reti regression intentionally retains ten review candidates, compared with
five under the old suppression. The original five caps of 3–24 are preserved.
Runtime bounds additionally establish a 128-step byte walk and three uint64
ceilings. Those facts alone establish no budget coverage. Default security
finding baselines are independent of this review-candidate API.

## Work limits and remaining precision limits

Each induction candidate has 2,048 expression/writer visits, with a bounded
physical-phi walk and scratch recursion depth. At most 32 immediate scratch
slots are considered per guard. Copy/phi queries visit at most 256 values. The
numeric fixed-point engine admits 128 dependencies and 4,096 transfer steps;
after widening it attempts four narrowing passes and publishes the last checked
state. A failed proof attempt does not publish its partial iterate.

Cost proofs admit 4,096 reachable blocks per invocation, at most 64 nested call
queries and 256-bit composed visit counts. Nested costs conservatively multiply
per-invocation bounds and sum alternative blocks. They do not yet derive
amortized bounds for counters shared between loops. General relational ranking
functions, nonlinear progress, arbitrary scratch aliases and recursive cost
summaries remain outside the proved fragments. The interval fixed point can
still produce useful value bounds in some of these cases.

## Validation

The core controls include 320 generated counter programs across stack/scratch
storage, pre/post tests, ascending/descending strides, strict/inclusive guards
and boundary initial values. A separate concrete instruction interpreter checks
observed visits, values, costs and arithmetic failures. Further controls cover
multiple backedges, equality residues, resets, dynamic aliases, nested loops,
callee rejection, guaranteed credit, stale revisions and proof exhaustion.
There are 49 new core test cases, in addition to the expanded budget regressions.

Twenty-four private-interpreter cases compare predicted numeric and cost bounds
with read-only execution of original TEAL. They cover stack and scratch loops,
pre/post tests, guarded runtime limits, variable positive steps and rejection of
an out-of-range argument. No transaction is signed or submitted.

The combined private-interpreter, assembler and pinned external-fixture gate
passed **99 checks in 59.02 seconds**. The disposable node was stopped and
removed afterward. A fresh non-editable wheel passed the existing public-API
smoke checks, recursive-return checks and the new scratch-loop cap, exit-range
and finite-cost queries in an isolated environment without Puya.

| Gate | Result |
| --- | --- |
| Full backend/corpus suite | 6,344 passed, 98 intentional skips in 988.69 seconds. |
| Complete core-only suite | 4,843 passed, 379 intentional skips in 433.50 seconds, with Puya absent. |
| Private interpreter, assembler and external fixtures | 99 passed in 59.02 seconds. |
| Fresh non-editable wheel | Passed existing APIs, recursion, loop induction, intervals and costs without Puya. |

Combined statement/branch coverage is **88.70%**: 90.71% of statements and
84.66% of branches. The interval-query engine rises from 84.96% to **89.34%**
combined coverage. The new induction checker has 85.13%, fixed-point engine
94.67%, upper-cost module 89.08%, and shared loop graph 96.15%.
All 231 per-program default finding comparisons and the performance gates pass.
Ruff and diff whitespace checks also pass.

The 98 full-run skips comprise 75 private runtime tests, nine assembler tests,
twelve external-example tests, opt-in digest regeneration and the existing
non-AVM fixture lifting refusal. The private gate separately passes the
infrastructure-dependent checks. Core skips also reflect the absent compiler.

Full-run source SHA-256:
`609617aa400be612a8d1b3ee619550140f8ab6faaf9545ac3a1d3a8181d5d47c`.
The hash concatenates sorted `src/**/*.py` paths, NUL, contents and NUL.
The later source adjustments correct the public trip-cap docstring and trim
trailing blank lines;
executable AST and statement locations are unchanged. Final source SHA-256:
`fc0774422042139f65a64424d7f4257058ed4270f1a11f452a18aa3b4b4a745a`.
The rebuilt and rechecked wheel exactly matches that final source. Its SHA-256:
`61ea6a1e62230acc5d1b77a2e7f3354b1c21c37c56dc1cc937bae23c50ffcb0d`.

The local artifacts use `/tmp/tealql-loop-`: `full.log`, `core.log`,
`private.log`, `interpreter.log`, `coverage.json`, `source.sha256`,
`final-source.sha256` and `wheel-final.log`.
The wheel is `/tmp/tealql-loop-dist/tealql-0.1.0-py3-none-any.whl`, installed in
`/tmp/tealql-loop-wheel-env`.

Reproduction commands for the locked test environments:

```sh
LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1 \
  COVERAGE_FILE=/tmp/tealql-loop-full.coverage \
  .venv/bin/python -m pytest tests/ -q -ra -n 3 --dist=worksteal \
  --cov --cov-report=term:skip-covered \
  --cov-report=json:/tmp/tealql-loop-coverage.json
/tmp/tealql-review-core-env/bin/python -m pytest tests/ -q -ra \
  -n 2 --dist=worksteal
TEALQL_LOCALNET=1 TEALQL_EXTERNAL_FIXTURES=/tmp/tealql-external-evaluation \
  ALGOD_ADDRESS=http://127.0.0.1:41980 TEAL_ALGOD_LOCAL=http://127.0.0.1:41980 \
  .venv/bin/python -m pytest tests/test_behavioral_localnet.py \
  tests/test_assembler_differential.py tests/test_external_evaluation.py -q -ra
```

The private node uses the same pinned image and configuration as
[the behavioral workflow](../.github/workflows/localnet.yml); its published port
is restricted to localhost. Full and core suite wall times overlap and are not
an isolated performance comparison.
