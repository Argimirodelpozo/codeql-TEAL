# Recursive return refinement

Implementation commit: `dd13d3d1` on `rev`.

Legacy recursive helpers can now retain their different physical return stacks
through an immediate flag guard. For example, a helper returning `[value, 1]`
on success and `[0]` on failure lets its caller recover `value` after `assert`.
This works across self recursion, mutual recursion and supported non-tail
recursive paths. An unresolved cycle previously left those operands unknown.

The improvement concerns construction SSA and the analyses that consume it.
Ordinary fixed-width recursive results continue to use cyclic phis. Compiler
lowering of divergent recursive legacy routines remains a separate limit.

## Proof and integration

The solver finds strongly connected components in the routine execution call
graph. It targets cycles containing a known divergent legacy routine and also
analyzes their callee dependencies. The graph follows execution through shared
tails, using the same execution-body enumeration as the canonical simulation.

Each routine starts with symbolic incoming arguments. Each return alternative
retains a complete physical stack of source values and argument references.
Calls substitute their actual arguments into the callee's alternatives. Joins
retain distinct stacks, including different depths. Literal integer flags and
canonical branch polarity filter alternatives; unknown flags remain possible on
both outcomes. Ordinary opcodes use the existing `stacksim._exec` transfer.

The fixed point begins with no known normally returning calls in a cycle and
monotonically adds alternatives. Only a stable, complete component is published.
It is therefore impossible to publish just the base cases while a recursive
path is still being discovered. Trial states do not allocate public SSA phis.

The proven maximum return width must agree with the existing arity inference.
Any newly discovered variable-depth member is marked before call pairing and
frame-height analysis, including a member with one physical `retsub` that
forwards its peers' alternatives. The canonical walk then uses the complete
return stacks at recursive call sites, even before their return blocks have
been walked. Direct parameter returns bind to each actual call: two callers
passing 11 and 77 retain their separate values.

Call ordering is also iterative. Long call chains and large cycles no longer
depend on Python's recursion limit.

## Bounds and limits

The query permits 100,000 transfer/state steps, 32 alternatives per block or
routine, and 4,096 retained cells per routine walk and across return summaries.
Exhausting a bound discards the unfinished component. Complete independent
callee summaries can still be retained.

The proof refuses frame operations, `proto` callees, unknown instruction stack
effects, paths that may consume caller-owned cells, unavailable continuations,
incomplete callee summaries, and disagreement with the inferred return width.
Growing recursive stacks can exhaust the alternatives bound. A cycle with no
proved normally returning alternatives does not supply a fabricated result.
Refusals appear in analysis health as `recursive-return-refinement`.

Caller guard refinement still requires one local predecessor and an immediate
`assert`, `bz` or `bnz`. Other predecessors and collapsed branch arms retain the
conservative behavior. Shared frame accesses require their existing frame proof.

The value graph retains recurrences such as `phi(42, result + 1)`. This change
does not compute a termination proof or an inductive numeric bound; general
recursive arithmetic can still have unknown intervals. Source-value identities
also merge facts across invocations, so arbitrary calling-context correlations
are outside this proof.

## Validation

Twenty-seven core controls cover both branch polarities, non-Boolean flags,
direct and mutual recursion, non-tail recurrences, source-order changes, actual argument binding,
acyclic dependencies, local loops, late-discovered values and whole-cycle refusal.
Two 1,500-node call graphs check iterative ordering, with and without a cycle.

Eighteen private-interpreter controls pair SSA predictions with read-only
execution of original TEAL at depths 0, 1 and 3. They cover successful and
rejected self, mutual and non-tail recursive calls, with independently expected
logs and preservation of the caller's 55. They do not require the optional
compiler to lower divergent recursive routines.

The initial focused run exposed seven existing precision gaps and one missing
new-module test hook; its two conservative controls already passed. A later
numeric test incorrectly required an interval for a general recurrence. It now
checks that the recurrence cannot collapse to its base constant and that any
available interval includes independently calculated finite executions.

The first private-interpreter attempt reached the disposable node during
startup and failed in fixture setup. After the health endpoint became ready,
all 18 cases passed in 7.20 seconds.

| Gate | Result |
| --- | --- |
| Focused recursion, stack, frame and health controls | 73 passed in 21.40 seconds. |
| Benchmark, graph, visualization and pass-inventory checks | 173 passed in 52.51 seconds. |
| Corpus and representation regression checks | 616 passed, 1 opt-in digest-regeneration skip in 426.93 seconds. All 231 default detector rows match the existing baseline. |
| Combined private-node, assembler and external gate | 75 passed in 77.83 seconds. The disposable node was stopped and removed afterward. |
| Full backend/corpus suite with coverage | 6,295 passed, 74 intentional skips in 1,178.65 seconds. Combined statement/branch coverage is 88.71%, above the 68% gate. |
| Complete core-only suite | 4,794 passed, 355 intentional skips in 521.10 seconds, with Puya absent. |
| Fresh non-editable wheel | Passed in an isolated core-only environment without Puya, including CLI, public analysis APIs, guarded returns, shared contexts and recursive return refinement. |

Coverage is 90.72% of statements and 84.66% of branches. The new recursive-return
module has 89.33% combined coverage. The full run also passed the absolute-cost,
SSA construction scaling and scratch lookup scaling checks. Full and core runs
overlapped; their wall times do not isolate performance changes.

The 74 full-run skips comprise 51 private runtime tests, nine assembler tests,
twelve external-example tests, opt-in digest regeneration and the known lifting
refusal for the non-AVM `sha512_digest_recipient.teal` taint fixture. The combined
private gate separately passed the infrastructure-dependent checks. Core skips
additionally reflect the deliberately absent compiler. Ruff and diff whitespace
checks also pass.

Validation source SHA-256:
`c5107d72fada33c65848d98861c74f6c9194324eacbc840b15f9f4c0805a1412`.
The hash concatenates sorted `src/**/*.py` paths, NUL, contents and NUL.
Local evidence uses the `/tmp/tealql-recursive-` prefix, including
`controls.log`, `baselines.log`, `corpus-final.log`, `private.log`,
`interpreter.log`, `interpreter-final.log`, `full.log`, `core.log` and
`coverage.json`. Both complete suites, the private gate and the wheel used the
same source hash, verified again after the full run finished.

The verified wheel is `/tmp/tealql-recursive-dist/tealql-0.1.0-py3-none-any.whl`,
SHA-256 `3cbd023f18d31a1449bab11bd52be1f1bfc7132f6cecd2898d1e8c53e0d26a6a`.
Its isolated installation is `/tmp/tealql-recursive-wheel-env`; smoke-test
evidence is in `/tmp/tealql-recursive-wheel.log`.

Reproduction commands for the locked environments:

```sh
LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1 \
  COVERAGE_FILE=/tmp/tealql-recursive-full.coverage \
  .venv/bin/python -m pytest tests/ -v -ra -n 3 --dist=worksteal \
  --cov --cov-report=term:skip-covered \
  --cov-report=json:/tmp/tealql-recursive-coverage.json
/tmp/tealql-review-core-env/bin/python -m pytest tests/ -q -ra \
  -n 2 --dist=worksteal
```

With the pinned disposable node and external fixtures provisioned, the combined
private gate used:

```sh
TEALQL_LOCALNET=1 TEALQL_EXTERNAL_FIXTURES=/tmp/tealql-external-evaluation \
  ALGOD_ADDRESS=http://127.0.0.1:41980 TEAL_ALGOD_LOCAL=http://127.0.0.1:41980 \
  .venv/bin/python -m pytest tests/test_behavioral_localnet.py \
  tests/test_assembler_differential.py tests/test_external_evaluation.py -q -ra
```
