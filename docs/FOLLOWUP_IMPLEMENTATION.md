Follow-up implementation
========================

Work continues on `rev`, starting from `93fd8a57`. Validated changes are committed
and pushed to `origin/rev` as requested. The earlier review implementation and
its validation remain recorded in `REVIEW_IMPLEMENTATION.md`.

- [x] Connect storage-authority provenance and explicit guard evidence to existing detectors.
- [ ] Fix or precisely classify the 7 unresolved return slots, 13 missing operands, and 10 shared execution blocks in the corpus census.
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
