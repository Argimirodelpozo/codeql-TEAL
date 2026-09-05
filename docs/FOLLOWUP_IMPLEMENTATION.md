Follow-up implementation
========================

Work continues on `rev`, starting from `93fd8a57`. Validated changes are committed
and pushed to `origin/rev` as requested. The earlier review implementation and
its validation remain recorded in `REVIEW_IMPLEMENTATION.md`.

- [x] Connect storage-authority provenance and explicit guard evidence to existing detectors.
- [x] Fix or precisely classify the 7 unresolved return slots, 13 missing operands, and 10 shared execution blocks in the corpus census.
- [ ] Consolidate guard/fact consumers, retire redundant paths, and reduce oversized modules.
- [ ] Expand independent behavioral fixtures, add an unseen family evaluation, and improve taint/callee-effect coverage.
- [ ] Deepen authority, box permissions, relational groups, crypto/replay, lifecycle, conservation, resource sufficiency/recoverability, and revision compatibility analyses.
- [ ] Secondary priority: loop invariants, numeric call summaries, relational intervals, and divisibility/bit integration.
- [ ] Validate the final core/backend/node behavior and full suite; record classified baseline changes and remaining limits.

Progress is recorded below with each implementation. A checked milestone requires
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
application addresses, or unrestricted writers. It does not prove temporal
revocation/freshness of a previously loaded authority. The work budget is bounded
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
Ruff and the finding-digest manifest check pass. Broader architecture, behavioral,
SAST-fragment, interval, and final full-suite work remains below this milestone.

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
