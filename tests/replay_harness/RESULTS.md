# Replay harness — results

## Sampled historical replay on real mainnet state (time-travel, 2026-10-14)

The dryrun gates below run each program alone, with empty state and synthetic
inputs, so they mostly exercise routing and guards. `timetravel.py` +
`ttreplay/` close that gap: they re-evaluate **real mainnet blocks** with
go-algorand's own evaluator. Ledger state at the round before each block comes
from a time-travel algod ([d13co/go-algorand@timetravel](https://github.com/d13co/go-algorand/tree/timetravel),
public at `mainnet-api-dt.d13.co`). Each block is evaluated twice, once with
the deployed program and once with the lift-recompiled one. The deployed run
must reproduce the chain's ApplyData byte for byte. The lifted run's ApplyData
(logs, inner transactions, global/local deltas) and box writes must then match
exactly. See `README.md` for the oracle and its self-test.

**Batch 1: 9 high-volume apps, 30 blocks each across each app's lifetime,
21 program versions.** These are the top callers in a 60-block sample of the
last year: Tinyman v2, two swap aggregators, an ORA-style miner, a TEALScript
app, a v5 PyTeal-era app, and others.

| app | blocks | groups | FAITHFUL | DIVERGES | over budget | cost ratio (median) | programs | coverage of deployed code by real traffic |
|---|---|---|---|---|---|---|---|---|
| 1002541853 (Tinyman v2) | 30 | 61 | **61** | 0 | 7 | 1.01 | 1 | 42% |
| 1284326447 | 30 | 95 | **95** | 0 | 0 | 1.02 | 1 | 65% |
| 3172554435 | 30 | 30 | **30** | 0 | 0 | 0.99 | 4 | 2–64% |
| 1222048105 | 30 | 30 | **30** | 0 | 0 | 0.98 | 1 | 72% |
| 641500474 | 30 | 31 | **31** | 0 | 0 | 1.00 | 1 | 63% |
| 1439234347 | 30 | 54 | **54** | 0 | 0 | 1.00 | 1 | 79% |
| 1786969481 | 30 | 37 | **37** | 0 | 0 | 1.01 | 7 | 1–64% |
| 3192677198 | 30 | 30 | **30** | 0 | 0 | 1.00 | 2 | 18–23% |
| 1040271396 | 30 | 30 | **30** | 0 | 0 | 0.95 | 2 | 26–28% |

**398/398 groups FAITHFUL, 0 DIVERGES.** One of them is an UpdateApplication
installing an AVM 9 program, which the AVM refuses as a "downgrade" from the
lifted program's AVM 10; that block is re-run with the lifted new program
installed instead (at a matching version, its clear program too), and the
update and everything after it behave as on chain. Recompiled programs spend about the same
pooled budget as the originals (median 0.95–1.02×). Tinyman's groups are
budget-exact (the deployed program used 2,096 of a 2,100 pool), so 7 groups
needed 13–30 more opcodes than the chain gave them. Those were judged on a re-run
with extra budget and were exact. Coverage is the honest limit: real traffic
exercises 1–79% of each program, so this validates the paths users take, not
the whole program.

**Batch 2: 21 more apps, 20 blocks each.** These are the next tier of callers,
including apps reached only through inner calls and apps since deleted, which
are replayable from history. **Every group was FAITHFUL**, with 0 DIVERGES and 0
lift failures. One more app (971323141) has budget-exact groups: 7 needed a
little more budget than the chain gave them and were exact with it.

**Combined: 30 apps, 664 blocks, 912 groups, 45 program versions: 912
FAITHFUL, 0 DIVERGES.** 100 groups predate AVM 10 and
were replayed under the current protocol. The deployed program's chain
reproduction showed that upgrade changed nothing. Median pooled-budget
ratio per app is 0.87–1.08.

**It found a real lift bug.** 3192677198's second program version (5 of 30
blocks) did not lift. Two reads of one owner key were typed `account` and
`uint64`, and Puya's CSE merged them ("incompatible types on assignment").
`_infer_state_types` had counted the read witnesses and a constant put as
rival claims. After the fix, all 5 blocks are FAITHFUL (`test_state_type_unification.py`).

**Oracle problems found and fixed on the way.** Each one is pinned by
`test_replay_harness.py` or the README:
- **Block prefix:** a target-only replay misses same-block writes, so the
  whole prefix is replayed.
- **Version cap:** the lift's AVM ≥ 10 is rejected by old blocks' protocols,
  so those blocks are re-run under the current protocol.
- **Version downgrade:** an update installing an older-AVM program is refused
  once the lifted program raised the version, so the lifted variants install
  the lifted new program instead (ttreplay `installs`).
- **REST rewards view:** the stored rewards base had to be recovered from
  `reward-base` and `pending-rewards`.
- **Poisoning:** any non-faithful group poisons the rest of its block,
  including a failed one, because the chain committed it.
- **Extra budget changes behaviour:** OpUp loops read `global OpcodeBudget`
  and create fewer inner apps, which shifts every later created app ID in the
  block. Extra budget is therefore only a fallback, and only for the reported
  groups.

