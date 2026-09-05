Follow-up implementation
========================

All six follow-up milestones and final validation are complete on `rev`, building
on `93fd8a57`. Validated changes are committed and pushed to `origin/rev` as
requested. The earlier review implementation and its validation are recorded in
`REVIEW_IMPLEMENTATION.md`.

- [x] Connect storage-authority provenance and explicit guard evidence to existing detectors.
- [x] Fix or precisely classify the 7 unresolved return slots, 13 missing operands, and 10 shared execution blocks in the corpus census.
- [x] Consolidate guard/fact consumers, retire redundant paths, and reduce oversized modules.
- [x] Expand independent behavioral fixtures, add an unseen family evaluation, and improve taint/callee-effect coverage.
- [x] Deepen authority, box permissions, relational groups, crypto/replay, lifecycle, conservation, resource sufficiency/recoverability, and revision compatibility analyses.
- [x] Secondary priority: loop invariants, numeric call summaries, relational intervals, and divisibility/bit integration.
- [x] Validate the final core/backend/node behavior and full suite; record classified baseline changes and remaining limits.

Results are recorded below with each implementation. A checked milestone requires
an implemented capability and meaningful validation, not merely an API or a test
that reproduces its own implementation. Unsupported cases retain explicit limits.

Authority integration
---------------------

Default lifecycle and lifted taint detectors now share a revision-scoped writer
analysis with the opt-in authority obligation. Constant addresses, the immutable
creator, and the current app's `AppCreator` alias are recognized. Static global
and local keys require every potentially aliasing writer to preserve authority;
this includes dynamic-key writes, deletion, creation, and guarded rotation.
Caller/method seeds cannot establish a whole-program writer invariant.

Storage preservation is conditional: initial contents, other writers, and prior
or future program revisions remain explicit premises. Default reports carry
these premises as incomplete analysis, and lifted guards expose structured
evidence. Input-check dependency remains distinct from a proved predicate.
Sender must be an exact alias through copies and every join arm; merely using
Sender in a calculation no longer establishes an identity check.

The supported fragment does not establish authority for foreign mutable state,
addresses extracted from packed records, unresolved scratch, arbitrary computed
application addresses, or unrestricted writers. Temporal freshness is added in
the later SAST milestone below. The work budget is bounded
and exhausted/unsupported queries cannot become authority proofs.

Validation: 124 combined detector/benchmark/contract regressions passed, as did
96 core-only checks. The 220-case curated benchmark is unchanged (94 true
positives, 126 true negatives). The full 231-program offline corpus comparison
completed without detector crashes. Changes affect 72 policy cells in 37
programs: seven detector totals move when unproved authority credit is removed.
`AUTHORITY_FINDINGS_REVIEW.json` records every old/new cell and the rejected
authority sites/reasons. These are candidate finding changes, not verified
vulnerabilities. The timelock decreases accompany reclassification into the
unprotected lifecycle policies; they do not assert an improved time delay.

The corpus comparison caught a shared-helper self-rotation precision regression;
the final implementation handles it inductively and keeps its history premises.
Ruff and the finding-digest manifest check pass. Subsequent sections record the
architecture, behavioral, SAST, numeric and final full-suite results.

Representation census
---------------------

All seven declared-return entries are resolved: four were non-returning callees,
and three omitted call results at continuations that are also branch targets.
The latter now retain distinct call-result and control-flow merges, including
recursive returns; a direct branch can no longer erase the returned alternatives
or make their joined value appear constant.

`REPRESENTATION_GAPS.md` and `tests/representation_gaps.json` classify every
remaining site. Six missing operands need nested caller-residual summaries;
seven need a relationship between a legacy return flag and its stack depth.
Four shared blocks consume incoming effect operands, and six share only control
flow without an incoming stack operand. Their counts remain explicit, with
location-level regressions in addition to the existing per-program ceilings.

Validation: 409 frame/lift/adversarial checks passed; 53 backend/fact/return checks
passed with the real Puya backend enabled; 25 gap/manifest checks passed. The
regenerated census covers all 857 parse and 231 representation inputs, with
97,077 consuming instructions and zero declared-return gaps. All 231 default
finding rows are unchanged from the authority milestone, with no crashes.
Core-only validation adds 43 passing checks and one expected backend skip.

Fact and guard consumers
------------------------

Taint graphs, transaction-field reports, call discovery, and state target
resolution now request immutable facts. Querying them does not invalidate a
caller's existing fact view or rewrite its operands. Reports retained across a
legacy propagation pass refresh their fact revision. Proven phi identities join
the shared alias relation; the detector-specific recursive copy resolver is
retired. Its mutation gate now breaks the shared relation and still detects a
benchmark regression.

Guard classification, evidence, and bounded definition walks live in
`lift/guards.py`, with compatibility imports retained. `fund_flow.py` shrinks
from 1,379 to 967 lines. Constant state-target resolution is separate from call
traversal, reducing `intercontract/analysis.py` from 802 to 657 lines.

State targets require a dominating initialization in the current invocation,
the correct local account, and agreement of all potentially aliasing writers.
Dynamic keys, partial mutations, foreign box writes, and existence flags cannot
silently produce a constant target. Historical initialization alone is
insufficient. Box initialization is currently limited to the same basic block
with no intervening inner submit. Global/local initialization can cross inner
submits: AVM writes address the running app and app re-entry is forbidden by
the [pinned evaluator](https://github.com/algorand/go-algorand/blob/da5946a14568c0cbaa2c9daf4241882de12f3c16/data/transactions/logic/eval.go#L5595).

`cross_detection_result` retains standard health metadata. Its legacy list
projection remains available. Missing, dynamic, and depth-limited call edges,
detector crashes, and authority premises now reach `xcontract` and `audit` JSON,
text, and exit status 2. Incomplete execution does not inflate finding counts.

Validation: 422 integration checks, 65 core-only checks (two backend skips),
and 34 checks with the Puya backend enabled passed. The 231-program offline
finding comparison has no changed cells and no crashes. Four report lines now
render source-established `itob(0)` values as eight zero bytes; the reviewed
snapshot records that precision change. Ruff and diff whitespace checks pass.

Numeric facts
-------------

`NUMERIC_ANALYSIS.md` documents the implemented fragments and their bounds.
Congruences now establish inductive loop residues and reduce interval endpoints;
integer difference constraints close transitive guard relations. Numeric call
summaries compose straight-line proto helpers while retaining call identity,
argument order, multiple returns, and frame replacement. The rounding obligation
uses divisibility facts for variable expressions. Exhaustion, unsupported effects,
branching/recursive callees, and incomplete representations retain unknowns.

Validation includes 228 integration checks, 97 core-only checks, and independent
integer oracles over loops and uint64 arithmetic. The 231-program offline finding
comparison remains unchanged without crashes. Subsequent sections record
expanded node observations and deeper SAST inference.

Behavioral and independent evaluation
-------------------------------------

The simulator compares full atomic groups established by a creation prefix at
one pinned ledger round. Original and lifted transaction inputs must match
apart from the initial approval code. Six group fixtures exercise existing
global/local state, boxes, inner payments, scratch sharing, group fields, and
lifecycle transitions. Five numeric fixtures compare known concrete outputs;
the earlier creation and deliberate-state-change fixtures remain in the gate.
Foreign-box ownership, application-parameter changes, and clear-state rollback
still require richer observations and remain inconclusive.

The concrete callee oracle found reversed multi-output identities in residual
summaries. Wide arithmetic now retains stack order, and constant `addw`/`mulw`
outputs can be rematerialized across the call. A private interpreter regression
first diverged and now matches the original's expected values. The taint graph's
capped path queries now select the shortest paths before truncation, including
across source/sink pairs; exhaustive permutation oracles check the result.

Six upstream examples were frozen before evaluation and have distinct syntax
families absent from the existing corpus. `EXTERNAL_EVALUATION.md` preserves the
first adapter failure and the completed evaluation without claiming a reused
holdout. All six parse and recompile without representation gaps or backend
diagnostics, and all 24 default app detectors complete. Exact policy finding
locations are recorded without treating them as verified vulnerabilities.

Validation: 173 focused tests passed; combined statement/branch coverage in that
run is 78% for the taint graph and 82% for callee effects. Core-only validation
passed 111 tests with six external skips. All 25 private runtime/assembler tests
passed; the external gate and observation tests add 34 passes. All 15 external
provenance/evaluation/assembly checks also passed against the private node. The 231-program
finding comparison remains unchanged with no crashes. Deeper SAST inference and
final full-suite validation are recorded below.

Deeper SAST inference
---------------------

`SAST_INFERENCE.md` records implemented fragments and explicit unknowns for all
eight directions. Authority uses infer read freshness; replay checks combine
accepted fixed-width signatures with a monotone consumed-key writer invariant;
proposal checks infer creator-authorized proposal/time pairs. Funding checks
infer actual group roles, and a bounded linear solver relates actual inner
payment amounts to incoming funding. Numeric congruences provide exact-division
facts for the rounding obligation.

Closed box call traces now infer and propagate family marks. Quantitative
resource bounds preserve allocation peaks, values read before resize and pooled
fee/inner-count limits, with conditional retry credit witnesses. Revision
comparison normalizes actual implementation traces while preserving traps,
state/log/scratch effects and implicit program dependencies. Branches, calls,
mutable environments and exhausted bounds remain unknown where unsupported.
These opt-in checks share immutable facts and bounded trace/flow machinery.

Review found and fixed numeric byte comparisons folded through illegal operand
types or encoded widths greater than 64 bytes. Resource cost includes possible
assembler-generated constant tables, and expression DAGs have node, depth and
coefficient bounds. The private interpreter independently confirms the byte
boundary, source cost allowance and constant revision agreement/difference.

Validation: 157 combined focused tests passed, as did the same 157 in the core
environment without Puya. An additional 113 numeric/state/resource integration
checks passed after the last resource changes. All five new private runtime
controls passed. The complete 231-program offline finding comparison has zero
changed cells and no crashes. Ruff and whitespace checks pass. The final full
suite, core suite and combined backend/private-node results are recorded below.

The final semantic review also restricted removable scalar reads to a whitelist
of total fields. Timestamp lookups and current-transaction effect reads can
fail even when their values are discarded. All 38 revision tests pass, and three
additional private controls confirm those interpreter failures. The first full
run was deliberately interrupted to include this fix in the complete gate.

The visualization inventory then identified nine modules added during these
milestones that still needed catalog decisions. New scalar views expose
authority premises, congruences, numeric call results, resource bounds and
cross-contract health; shared helpers have explicit support classifications.
All ten catalog tests pass both with and without Puya, including rendering every
view/graph and semantic checks of the new results. The second full run was
interrupted to include this integration in the final gate.

The coverage run exposed two legacy tests using the shared walk-depth constant
through `fund_flow`. The guard behavior assertion passed, but the compatibility
export was missing after extraction. Restoring that one export fixes both
unchanged tests; all 52 tests in the two review modules and the lifted fund-flow
module pass. No guard depth or detector verdict was changed by this repair.
That third run was interrupted and superseded by the complete final run below.

Final validation
----------------

The final source implementation is `563b4425`; subsequent edits only record
validation. The complete final run used that source without further edits.

| Gate | Result |
| --- | --- |
| Full suite with compiler corpus, backend and branch coverage | 6,249 passed, 47 intentional skips in 1,334.90 seconds. Combined statement/branch coverage is 88.68%, above the 68% gate. |
| Full core-only suite, with Puya absent | 4,748 passed, 328 intentional skips in 712.96 seconds. |
| Combined private-node, assembler and external-example gate | 48 passed in 210.98 seconds at `d18e0caf`; the later source repair only restores a compatibility export. |
| Guard regression modules after the compatibility repair | 52 passed in 7.55 seconds, including both originally failing tests unchanged. |
| Fresh non-editable wheel with lockfile-pinned core dependencies | CLI, spec data, policy/box/resource/revision APIs, catalog views and the compatibility export pass; Puya is absent. |
| Offline default finding comparison | All 231 rows unchanged from the reviewed authority baseline; zero crashes. |
| Static checks | Ruff and diff whitespace checks pass. |

The full-run skips comprise 24 private runtime tests, nine private assembler
tests, twelve external-example tests, opt-in digest regeneration, and one known
lifting refusal. The latter is the benchmark's non-AVM `sha512` fixture: its
taint behavior is tested, but it is not claimed to be a runnable AVM program.
The private/external gate separately exercises the infrastructure-dependent
checks. Core skips additionally reflect the deliberately absent compiler.

Final coverage is 90.71% of statements and 84.60% of branches. Combined coverage
is 87.80% in the analysis package, 93.00% in the taint graph and 82.28% in callee
effects. These are execution-coverage measures, not accuracy or security proofs.

Reproduction commands used the locked development environments:

```sh
LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1 \
  .venv/bin/python -m pytest tests/ -v -ra -n 3 --dist=worksteal --cov
/tmp/tealql-review-core-env/bin/python -m pytest tests/ -q -ra -n 2 --dist=worksteal
TEALQL_LOCALNET=1 TEALQL_EXTERNAL_FIXTURES=/tmp/tealql-external-evaluation \
  ALGOD_ADDRESS=http://127.0.0.1:41980 TEAL_ALGOD_LOCAL=http://127.0.0.1:41980 \
  .venv/bin/python -m pytest tests/test_behavioral_localnet.py \
  tests/test_assembler_differential.py tests/test_external_evaluation.py -q -ra
```

The local full-suite log and coverage JSON are
`/tmp/tealql-followup-full-tests4.log` and
`/tmp/tealql-followup-full-coverage4.json`. Core and private logs are
`/tmp/tealql-followup-core-tests.log` and
`/tmp/tealql-followup-combined-node2.log`. The verified wheel is
`/tmp/tealql-followup-dist/tealql-0.1.0-py3-none-any.whl`, SHA-256
`2bc34c613d3c422c88379fe28e01df83c6006d650a351b31cf046deef82ff04d`.
The final source SHA-256 is
`702190c0c3d4e0c39452e78f0a35d411693aaa9e686ecfb80ffe959609c1ba37`,
hashing each sorted `src/**/*.py` path, NUL, contents, NUL in sequence.

The private node was stopped and removed after its gate. Behavioral fixtures use
read-only simulation; no transaction was submitted. Known limits remain in
`REPRESENTATION_GAPS.md`, `NUMERIC_ANALYSIS.md` and `SAST_INFERENCE.md`.
