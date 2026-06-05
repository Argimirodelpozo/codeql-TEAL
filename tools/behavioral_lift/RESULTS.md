# Behavioural lift verification — results

Real-world generalisation + behavioural test for `WIP_lift2puyaIR`: take TEAL
the lift has never seen, lift it to Puya IR, recompile to TEAL, and check the
recompiled program behaves like the original by **executing both on a live
Algorand localnet** (algod dryrun) across a matrix of inputs.

Pipeline (`tools/behavioral_lift/`):
- `recompile.py` — `SSAProgram(db)` -> Puya IR -> split/destructure -> MIR ->
  TEAL text (`emit_teal`); assemble via localnet algod.
- `fetch_mainnet.py` — pull deployed approval programs from the public mainnet
  algod, disassemble via the localnet, build CodeQL DBs.
- `compare.py` — dryrun original vs recompiled across `{no-args, each routing
  selector} x {NoOp, OptIn, CloseOut, Update, Delete}`; compare the
  **approve/reject outcome** (program-counter normalised out). `err`-vs-`assert`
  differences keep the same outcome (both reject) and are reported separately as
  "fail-opcode-only", not as divergences.

## Validity — lift -> recompile -> assemble to valid bytecode

| corpus | recompiled+assembled |
|--------|----------------------|
| 15 disassembled-mainnet (explorer, in-repo)       | **13/15** |
| 20 freshly-fetched mainnet apps (incl. Tinyman v2) | **20/20** |
| 55 more freshly-fetched mainnet apps (diverse)     | **54/55** |

**~87/90 real contracts lift -> recompile -> assemble to valid bytecode.** The
fails are all rare, distinct lift gaps: a TEAL-optimiser explicit-check edge, a
type-recovery incompatible-assignment, and a phi-node-argument mismatch (no
systematic class). Recompiled TEAL spans 6–2842 lines (Tinyman v2 router 2842
lines -> 5509 bytes). NB: big proto/recursive mainnet contracts are slow to lift
(the fat-frame SSA-construction cost), not a correctness issue.

## Behaviour — execution on a live AVM

| corpus | behaviourally faithful | inputs (outcome-matched) | real divergences |
|--------|------------------------|--------------------------|------------------|
| explorer (13 that lift) | **13/13** | 315 | **0** |
| mainnet, first 20       | **20/20** | 380 | **0** |
| mainnet batch, 60       | **58/59** old code → **59/59** fixed | 1180 (127 both-APPROVE) | **1** real bug → 0 |

### The test found and drove a real fix

On the second, larger mainnet batch the differential dryrun caught a genuine
lift correctness bug: **app_1200031257** -- a v6 *bare-expression* program
(`txn Sender; global CreatorAddress; ==`, no explicit `return`) -- APPROVES
on-chain when sender==creator, but the lift recompiled it to an unconditional
reject. Cause: a block that falls off the end with no terminator was lowered to
`ProgramExit(0)`, discarding the stack top; falling off the end returns the top
implicitly, like `return`. **Fixed in commit 41b39067** (byte-identical for Puya
contracts, which always emit an explicit `return`); the contract now recompiles
to `... ==; return` and is behaviourally faithful (approve=10). This is the
behavioural test working as intended -- real execution surfaced a bug that
validity / structural checks never would.

**Confirmed after the fix**: a full fixed-code re-run of the 60-contract batch
gives **59 FAITHFUL / 0 DIVERGES / 1 SKIP / 0 TIMEOUT** -- every contract that
lifts is behaviourally faithful, the one skip is a pre-existing lift gap (not a
divergence). And the fix is **regression-clean**: the corpus+backend sweep
(`LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1`) is 510 passed / 5 failed,
where all 5 are pre-existing Tier-2 corpus gaps (call-arity + `gaid`/`gload`
type-recovery) that fail identically on the parent commit `41b39067~1` -- disjoint
from the `control()` terminator change.

**33/33 of the first 35 contracts are behaviourally faithful** — across 695 dryrun
inputs the recompiled program's approve/reject decision matches the original on
every one. Of those, **75 inputs APPROVE in both original and recompiled with
identical logs** (positive approve-path equivalence, not just reject-consistency
-- explorer 6, mainnet 69), and 175 differ only in the failure opcode (the
recompiled program uses `assert` where the original used `err`; both reject the
transaction -- a benign decompile->recompile artifact, not a behaviour change).

Caveat: empty-state dryrun (no foreign refs) mostly exercises the routing +
guard paths, so most inputs reject and the 75 approve-path matches are the bare
NoOp/OptIn/etc. that approve without state. It proves the lift never flips an
approve<->reject decision on the tested inputs -- the key safety property --
but deeper state-dependent approval logic needs per-contract state setup.

### The lift's frontier = the NEWEST contracts (coverage, not faithfulness)

A fourth batch of **42 of the newest mainnet apps** (IDs 2.3-2.9B, lift never
seen) was fetched, built, and behaviourally tested on the fixed code:
**24 FAITHFUL / 0 DIVERGES / 11 SKIP / 7 TIMEOUT**, 80 both-APPROVE matches.
Every contract that lifts is faithful (0 divergences across the whole batch), but
the skip+timeout rate jumps to ~43% vs ~2% on the earlier batches. **The skips
are lift-COVERAGE gaps, caught cleanly as failures (never silent wrong answers)**,
clustering into ~5 known classes: `l-stack too small for callsub` (x4 -- an
interprocedural stack-survivor variant the re-sim-all fix doesn't cover),
used-but-never-defined register (x3), incompatible-type assignment (x2),
`explicit condition check removed` (x1), non-uint64 branch condition (x1). The 7
timeouts are the known super-linear SSA-construction perf on big contracts (180s
per-contract cap). Takeaway: across **132 real contracts over 4 batches the lift
has produced exactly ONE behavioural divergence (app_1200031257, found+fixed)**;
the remaining work is lift *coverage/perf* on cutting-edge AVM contracts, not
faithfulness.

Reproduce: `python -m tools.behavioral_lift.fetch_mainnet /tmp/m && \
python -m tools.behavioral_lift.compare /tmp/m` (needs a localnet on :4001).
