External evaluation, 2026-09-05
===============================

Six public compiler examples were selected by path and frozen before running
SSA, detectors, or recompilation. The source is
[Puya revision 27751c364229ae3cd0334fe4071e61690b6879e4](https://github.com/algorandfoundation/puya/tree/27751c364229ae3cd0334fe4071e61690b6879e4/examples).
`tests/external_evaluation_manifest.json` records the selection time, revision,
paths, and full SHA-256 hashes. Downloads stay outside the repository; upstream
sources retain their upstream license.

The selected event, local-state-offset, Merkle-tree, boxed-struct, game, and
voting programs have six different normalized syntax families, none present in
the 857-program existing test corpus. Literal and label renaming alone cannot
create a new family. This is evidence of unseen syntax families in this project,
not a claim that all semantic relatives have been excluded. These examples are
now development regressions and must not be presented as a fresh holdout again.

The first attempt parsed and recompiled all six programs, but its result adapter
mistakenly iterated optional `detector.degraded=None`. That recorded 90 metadata
errors and lost those finding cells. `external_evaluation_first_attempt.json`
preserves this failed attempt. After fixing only the adapter, the completed
evaluation is in `external_evaluation_results.json`; both artifacts record the
same digest of the analyzer source. A regression checks absent metadata and
actual detector exceptions separately. Neither error can become a clean result.

| Example | Consuming instructions | Missing operands / returns / shared blocks | Backend diagnostics |
| --- | ---: | --- | ---: |
| EventEmitter | 54 | 0 / 0 / 0 | 0 |
| LocalStateWithOffsets | 43 | 0 / 0 / 0 | 0 |
| MerkleTree | 57 | 0 / 0 / 0 | 0 |
| ExampleContract (boxed struct) | 64 | 0 / 0 / 0 | 0 |
| TicTacToeContract | 178 | 0 / 0 / 0 | 0 |
| VotingRoundApp | 411 | 0 / 0 / 0 | 0 |

All 24 default app detectors complete on every example without crashes or
reported degradation. Their exact finding locations are recorded for review;
these are candidate policy results, not verified vulnerabilities or a labelled
precision/recall score. Recompilation and assembly do not prove runtime
equivalence. Runtime behavior is checked separately by the private synthetic
fixtures, including their explicit expected outputs.

Reproduce the evaluation:

```sh
uv run python -m tests.external_evaluation /tmp/tealql-external --fetch
TEALQL_EXTERNAL_FIXTURES=/tmp/tealql-external \
  uv run pytest tests/test_external_evaluation.py -q
```

To check assembly, additionally set `TEALQL_LOCALNET=1` and `ALGOD_ADDRESS` to the
pinned private node described in `TESTING_REVIEW_CHANGES.md`. The scheduled node
workflow fetches only the revision-pinned, hash-verified inputs and runs both
evaluation and assembly gates. Core tests check provenance and error handling
without downloads; the external and node gates skip unless explicitly enabled.
