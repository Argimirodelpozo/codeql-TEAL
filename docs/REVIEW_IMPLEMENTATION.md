Implementation of the September 4 project review
================================================

Scope: concrete correctness fixes, shared analysis contracts, test reliability,
and the bounded first milestones for all eight proposed analysis directions.
Research features must state their supported fragment and return unknown when
their assumptions or evidence are missing. They do not constitute whole-program
soundness claims.

- [x] Shared execution completeness; text/JSON/SARIF and strict behavior.
- [x] Behavioral observations, completion accounting, hermetic tests, localnet CI.
- [x] Program/instruction identity and source-map joins.
- [x] Positional call summaries; replace duplicate prototype traversal.
- [x] Shared effect/sink metadata and safe location/arithmetic diagnostics.
- [x] Pinned AVM specification and explicit frontend/backend support inventory.
- [x] Router lifecycle facts, coarse types, and selection/content dependency rules.
- [x] Secondary priority: interval precision at guards/joins/calls, bounded widening and overflow controls.
- [x] Guard evidence, frozen analysis inputs, revision caches and dependency contracts.
- [x] Corpus manifests, per-fixture gates, independent properties and core-only CI.
- [x] Authority provenance across methods: constant global keys and creator-guarded writers.
- [x] Shared-box permissions and owner effects: explicit closed application/call environment.
- [x] Relational atomic-group obligations: bounded difference constraints and complete supplied templates.
- [x] Cryptographic statement binding: exact fixed-width fields and accepted Ed25519 verification.
- [x] Lifecycle/upgrade obligations: exact proposal reads, elapsed delay and authority.
- [x] Rounding/conservation obligations: supplied linear identities, units and exact-division controls.
- [x] Resource sufficiency requirements: conditional requirements, with environmental closure unknown.
- [x] Revision compatibility: structural method/storage/permission/effect contracts.
- [x] Final validation results, including both lift gates and coverage.

Implementation and scope
------------------------

`reporting.registry`, the security runner, and directory scan now carry the shared
`AnalysisResult`/`AnalysisHealth` contract. Construction, detector, report, and
finding-render failures retain completeness notices. Empty scans and unsupported
language versions are incomplete. Suppressions cannot remove these notices, and
an incomplete scan cannot replace an accepted baseline.

Source identity survives selected-file taint queries, source-map lookup, and sink
verification. One immutable effect table drives the query and fund-flow sink
inventories, including deletion and box mutation. Call transfers use independent
return slots; the same summary service computes transitive effect dependencies.
Assertion dependencies explicitly make no sanitizer claim.

The analysis builder publishes frozen pre-IR snapshots. Mutable backend
construction remains separate. Summary reuse is tied to frozen inputs, and fact
queries reject stale program revisions. The interval query now consumes canonical
path predicates, derives arithmetic bounds at definitions, joins phi arms, and
falls back conservatively on recursion or budget exhaustion. Bitwise, remainder,
shift and square-root transfers have independent arithmetic controls.

Guard queries over frozen definitions share bounded memo tables, and untainted
call arguments skip unused guard classification. Frame-source filtering follows
only the read's binding and phi closure: it preserves edges across other
operations instead of repeatedly traversing the whole upstream SSA graph.
Regressions protect cache isolation, memory limits, cycles, and rule barriers.

Mechanical AVM metadata is generated from a pinned specification and verified
against separately pinned input hashes. New AVM 13 opcodes retain their operands;
unsupported compiler operations/fields fail explicitly. Fixed costs no longer
require the optional compiler. See [AVM_SPEC.md](AVM_SPEC.md).

All eight research directions have an initial opt-in implementation. These are
conditional, bounded analyses with explicit unknown results, not complete
automated contract verification. [OBLIGATIONS.md](OBLIGATIONS.md) describes each
supported fragment, policy schema, assumptions, and API. No default detector is
silently replaced by an experimental policy.

The changes consolidate semantic ownership rather than targeting a net line-count
reduction: one positional summary service, one effect inventory, generated opcode
facts, shared path refinement, and one behavioral observation/comparison layer.
The added features make total Python source larger; the implementation
measurement is 188 files and 47,732 physical lines, versus 174 and 46,508 in the
review. Generated JSON is excluded from those Python counts.

Migration notes
---------------

- `all` JSON adds `complete`, `notifications`, and per-analysis `executions`;
  scan JSON adds `complete`. `detections` retains its detector keys and adds
  `complete` and `notifications`. Text includes incomplete-analysis notices and
  SARIF uses invocation execution status. All three detection commands exit 2 on
  incomplete analysis, even if findings were suppressed or below the severity
  threshold. The strict library runner rethrows; the CLI translates strict
  analysis failure into exit 2.
- `run_all_result()` exposes text, count and health from one execution. Existing
  text/count APIs remain compatibility views. `ScanResults` exposes the same
  envelope while retaining sequence access and immutable notifications.
- Sink verification now says `NOT_FLAGGED` where a detector found nothing;
  this does not assert that a guard was proved. Match identities include source
  file and instruction, preventing line-number collisions across programs.
- `SubSummary.results` is positional. `asserted_params` replaces
  `checked_params`/`arg_validated`; influencing an assertion is not validation.
  Aggregate return-source views remain for presentation. Published analysis IR
  and summary/taint maps are read-only; transforms must use mutable construction.
  Mutable IR recomputes taint instead of reusing stale results.
- `box_access_permissions()` returns an `AnalysisResult`, retaining source and
  environment limitations. Resource requirements do not establish sufficiency.
- Behavioral comparison adds attempted/completed/error/incomplete counts and an
  explicit `INCONCLUSIVE` status. Callers must inspect status, not just a zero
  divergence count. The current private-node fixture uses simulation because
  the pinned go-algorand release removed dryrun.

Reviewed corpus changes
-----------------------

The exact Puya lifecycle-router decoder changes findings in 12 of 231 distinct
programs. Every changed finding set is a subset of its old set; only the following
six lifecycle policies change, with no new detector crashes. This records a
classified baseline change, not a claim that the corpus became less vulnerable.
The router regression independently enumerates all 12 legal selector cases and
rejects an unsupported multiplier.

| Policy | Old findings | New findings |
| --- | ---: | ---: |
| delete-funds-check | 400 | 244 |
| is-deletable | 400 | 244 |
| is-updatable | 375 | 217 |
| timelock-upgrade | 191 | 145 |
| unprotected-deletable | 203 | 90 |
| unprotected-updatable | 184 | 72 |

Validation and remaining limits
-------------------------------

Test architecture and oracle scope are detailed in
[TESTING_REVIEW_CHANGES.md](TESTING_REVIEW_CHANGES.md). The representation manifest
still records 7 unresolved return slots, 13 missing operands and 10 shared
execution blocks. The 42 reserved programs were already seen during development;
they are not an independent holdout. A genuinely unseen family evaluation, broader
ledger fixtures, and proofs outside the documented fragments remain future work.

- Ruff: passed for `src`, `tests`, and `tools`.
- Pinned AVM generator: source-hash verification and regeneration check passed.
- Private go-algorand node: 14 tests passed, including five successful simulation/
  effect controls and nine assembler differential checks (21.86 seconds).
- Wheel: built and installed into a fresh environment without Puya; generated
  AVM metadata, obligation analysis, and `all --json` ran from `site-packages`.
- Full core-only suite in a fresh locked installation without Puya:
  **4,461 passed, 297 skipped** in 10m15s, with four workers. Skips cover optional
  compiler/node checks and opt-in gates; the core assertions remain exercised.
- After the final frame/guard performance fixes: **317 affected tests passed**;
  the same selection without Puya had **314 passed, 3 skipped**. The previously
  timed-out `app_3550180073` digest case passed unchanged in **161 seconds** under
  coverage when run independently (the earlier full run exceeded its 540-second
  limit), and **121 seconds** in the final full run. No test timeout was increased.
- Full coverage run with both lift gates on September 5:
  **5,964 passed, 16 skipped** in **23m29s**, with four workers. All 231 corpus
  finding comparisons passed. The skips are 14 separately exercised private-node
  checks, explicit baseline regeneration, and one existing non-liftable fixture.
- Coverage: **90.09% statements**, **83.87% branches**, **88.02% combined**.
  The historical review measured 89.94%, 83.72%, and 87.86%, respectively; test
  counts are not directly comparable because aggregate corpus loops were split
  into independently reported cases.

The full-run commands use Python 3.12.12; the compiler installation has Puya
5.7.1. The behavioral extra pins py-algorand-sdk 2.11.1.

```sh
LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1 \
  .venv/bin/python -m pytest tests/ -q -ra -n 4 --cov

# After uv sync --locked --extra dev in a separate core-only environment:
python -m pytest tests/ -q -ra -n 4
```
