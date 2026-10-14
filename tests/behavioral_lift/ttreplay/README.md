# ttreplay — historical-replay oracle for the lift

`ttreplay` re-evaluates real mainnet blocks with go-algorand's own block
evaluator. It reads ledger state lazily from a **time-travel algod**
([d13co/go-algorand@timetravel](https://github.com/d13co/go-algorand/tree/timetravel)),
which serves every account, app, asset and box at any past round. Any app's
programs can be swapped for the evaluation. `../timetravel.py` uses it to check
that the lift-recompiled program does what the deployed one did, on real inputs
against real state. The older dryrun gates mostly exercise routing: they run
with empty state and synthetic inputs.

## How it works

- **Ledger.** `remoteLedger` implements `eval.LedgerForEvaluator` over the REST
  API at round B−1 (`?round=`, `/box?round=`, `/blocks/R?header-only`).
  Duplicate checks are a no-op, since the block was certified.
- **Evaluation.** `eval.StartEvaluator(..., Validate: false, Generate: false)`
  runs on the block's real header. Each transaction group runs with
  `TransactionGroup`. With `prefix: true`, every group before the last reported
  one runs too, so the reported groups see exactly the state they saw on chain.
  Without the prefix, groups miss same-block writes and stop matching.
- **Observation.** A tracer records each top-level transaction's computed
  `ApplyData`, the group's box writes (`KvMods`, which are not in ApplyData) and
  the PCs executed per app (coverage). `ApplyData.Equal` against the block's
  recorded ApplyData decides `match_chain`.
- **Variants.** One request evaluates the block once per variant, such as
  `orig` (no override) and `lifted` (approval override). The variants share one
  HTTP cache. With `cache_dir`, the cache also persists on disk: every query
  names a round, so answers never change and reruns cost nothing.
- **Prefetch.** go-algorand's `prefetcher.BlockReferences` warms the cache
  concurrently before evaluation.
- **Protocol override.** `protocol` evaluates under a given consensus version.
  The lift emits AVM ≥ 10, which older blocks' protocols reject, so the harness
  re-runs both variants under mainnet's current protocol. The `orig`-vs-chain
  comparison then shows whether the upgrade changed anything.
- **Installs.** A variant's `installs` maps the sha256 (hex) of a program a
  top-level create/update installs to replacement bytes. With a lifted (AVM ≥ 10)
  program in place, an update installing the chain's older-AVM program is
  refused as a version downgrade; the harness then re-runs the block installing
  the lifted new program (and the new clear program at the same version).
  Validate is off, so the rewritten transaction's group hash is not re-checked.

Logic signatures are not evaluated: they run during signature verification,
which `TransactionGroup` skips. App programs and inner transactions are fully
evaluated.

## Build

```bash
git clone --depth 1 -b timetravel https://github.com/d13co/go-algorand ~/tools/go-algorand-timetravel
cd ~/tools/go-algorand-timetravel && make crypto/libs   # or copy crypto/libs from a built checkout
GO_ALGORAND_DIR=~/tools/go-algorand-timetravel tests/behavioral_lift/ttreplay/build.sh
```

## Use

```bash
ttreplay asm    < prog.teal       # {"program": b64} | {"error": ...}
ttreplay disasm < prog.b64        # TEAL
ttreplay replay < request.json    # see Request / Response in main.go

python -m tests.behavioral_lift.timetravel 1002541853 --samples 30 --out tt_results
```

`TEALQL_TT_NODE` (default `https://mainnet-api-dt.d13.co`), `TEALQL_INDEXER`
and `TEALQL_TTREPLAY` configure the harness. The public node has
`EnableDeveloperAPI` off and serves one simulate group at a time. Neither
matters here: `ttreplay` only uses its read endpoints.

## Verdicts

| status | meaning |
|---|---|
| FAITHFUL | lifted ApplyData equals the chain's and its box writes equal `orig`'s |
| DIVERGES | anything else, with the first differing JSON path or the error |
| BUDGET | the lifted program ran out of opcode budget (a cost artifact) |
| AFTER_DIVERGENCE | a later group in a block where the lifted run committed different state; not counted |
| REPLAY_MISS / REPLAY_ERROR | the unmodified program did not reproduce the chain: an oracle problem, not counted |
| LIFT_FAIL / LIFT_TIMEOUT / ASM_FAIL | the lift could not produce a program |
| ORACLE_BROKEN | the per-app self-test failed (see below); the app's results are discarded |

**Self-test.** Before the first verdict for each app, the harness replays one
block with a mutant of the lifted program that logs an extra value at entry.
Every group must come back DIVERGES or BUDGET. This guards against an override
that silently fails to apply, which would make every run read FAITHFUL.
Mutants deeper in the program can legitimately survive, because real traffic
covers only part of the code. The summary's coverage column shows how much.
