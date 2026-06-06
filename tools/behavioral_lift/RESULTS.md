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
| newest 42 (IDs 2.3-2.9B)| **24/24** that lift (11 skip, 7 timeout) | 80 both-APPROVE | **0** |
| old-era 23 (IDs 60-230M)| **23/23** (0 skip/timeout) | 103 both-APPROVE | **0** |
| mid-era 40 (IDs 300-900M)| **38/38** that lift (2 skip) | — | **0** |
| era 40 (IDs 1.4-2.0B)   | **24/24** that lift (10 skip, 6 timeout) | 70 both-APPROVE | **0** |

**Across 7 batches (~240 real contracts, ~201 that lift) spanning EVERY mainnet
era (60M → 2.9B), the differential dryrun has found exactly ONE behavioural
divergence — app_1200031257, found and fixed.** Post-fix, every contract that
lifts is behaviourally faithful on every era. The skips/timeouts are lift
coverage/perf gaps (see frontier section), never silent wrong answers. This is a
comprehensive faithfulness result: the lift does not flip an approve/reject
decision on any tested real contract.

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
clustering into ~5 known classes: `l-stack too small for callsub` (x4),
used-but-never-defined register (x3), incompatible-type assignment (x2),
`explicit condition check removed` (x1), non-uint64 branch condition (x1).

**The `l-stack` class (x4) is now FIXED (commit 2013488a).** It bottomed out not in
the Python lift but in the CodeQL CFG library: `RetsubOpcode.getEntrypoint()` found
a retsub's owning subroutine by *nearest preceding callsub-targeted label*, which
mis-assigns retsubs when the linker interleaves subroutine bodies -> wrong/empty
`predictRetsubReturn()` -> missing `retsub->continuation` CFG edges -> ~24% of the
contract's ops orphaned (`bb=None`) -> partial lift + arity over-count -> l-stack.
Fixed to reachability-based ownership (`Subroutine.subroutineLocallyContains`). All
4 l-stack contracts now lift fully + behaviourally FAITHFUL; byte-identical on
contiguous-subroutine Puya DBs; corpus lift-semantics 511/4 (was 510/5, also fixed
`large_box_operations_NestedItemArrayUInt64`); full QL<->Python parity suite 659/1skip
unchanged. Re-testing the 11 newest-batch SKIPs: **4 -> FAITHFUL (the l-stack ones),
7 still SKIP** (the unrelated type-recovery / undefined-register / explicit-check
classes), 0 new divergences.

**ALL 7 of those remaining SKIPs are now SOLVED (2026-06-06) — each lifts AND is
behaviourally FAITHFUL (0 divergences).** The enabling realisation: Puya's
intrinsic argument-type check is **non-fatal** (`models.py::_check_stack_types`
is `logger.error`, not a raise — a passing corpus contract has 11 such uint64↔
bytes "mismatches"). Only an **Assignment** avm-type mismatch, a **bytes
ConditionalBranch condition**, and an **SSA-construction violation** are fatal, so
type recovery only has to get *those* right (forcing every operand type regresses
correctly-typed corpus webs). The fix chain (each gated on the live differential):
1. **uint64 branch conditions** (`type_recovery::_fix_branch_conditions`, c1d5f35f) —
   a bytes-typed bnz/bz condition is a recovery mislabel; relabel uint64 (the safe
   direction: a uint64 reaching a bytes op is tolerated).
2. **buried-param frame versioning** (`frame_resolution`, ab788e40) — `frame_bury -k`
   (a param slot reused as scratch) was un-versioned, so N writes collapsed to one
   register → SSA violation; version every bury.
3. **per-sub destructure + bad-read orphan retry** (`recompile::_destructure_with_orphans`,
   fe38beaa) — `destructure_ssa` mutates in place and is not idempotent, so the old
   whole-program orphan retry re-validated already-destructured subs and tripped
   "<reg> assigned multiple times" on their materialised phis. Run the per-sub
   pipeline once each, orphan retry at each validation point.
4. **mir define-in-all-subs** (9ed3ce94) — define a mir-dropped register in every sub
   that uses the name (first-match fixed the wrong one and never converged).
5. **AVM-version pragma** (85837767) — emit the source's real `#pragma version N`
   (floored at 10), not a hardcoded 10, so a v11 `block BlkFeeSink` contract
   assembles its own recompiled body.

Net: lift coverage on the newest AVM contracts went from a ~5-class SKIP frontier
to 0 — every formerly-skipped contract now lifts and is behaviourally faithful.

**Post-fix generalisation sweep (2026-06-06, 60 freshly-fetched unseen mainnet
apps, `/tmp/mainnet_overnight`): 59 FAITHFUL / 0 DIVERGES / 1 SKIP / 0 TIMEOUT.**
Zero behavioural divergences — the fix chain generalises cleanly to contracts the
lift had never seen. The lone SKIP (app_1200031141) is a **mixed-type scratch-load
phi**: `tmp%990 = phi(load A, load B, …)` where the slots hold uint64 on some
paths and bytes (concat) on others, so the phi-web reconciliation can't pick one
AVM type and Puya rejects the phi. It fails identically with the optimiser OFF, so
it is a genuine type-recovery limit (the same untyped-polymorphic-value frontier),
not an optimiser artdefact — left as a known rare gap rather than risk the
operand-forcing that regresses correctly-typed corpus webs. A 22-contract
regression sweep over the older `/tmp/mainnet_fresh` batch was 22/22 FAITHFUL / 0
DIVERGES, and corpus lift-semantics holds at 511/4.

**The 7 timeouts are CodeQL-side, not Python (diagnosed).** faulthandler sampling
put 59/59 samples in `graphs.py:load_graph` blocked on the `codeql database
run-queries` subprocess; direct timing confirms `run-queries` on these ~3900-line/
59-`proto` contracts runs **>240s (killed at 4:00)** — the standard CFG library's
`BasicBlock::Make<...MakeWithSplitting...>` machinery is super-linear on 59-
subroutine CFGs. So it's the **CodeQL CFG extraction query**, NOT the (already
optimised) Python phi-collapse. `load_graph` caches per-DB, so it's a one-time
first-analysis cost. Fix = optimise/simplify the CFG-library config or move basic-
block reconstruction into PySSA — both suite-path + risky, left for review.

Takeaway: across **~240 real contracts over 7 batches (explorer + 6 mainnet eras)
the lift has produced exactly ONE behavioural divergence (app_1200031257,
found+fixed)**; every contract that lifts is faithful. The remaining work is lift
*coverage* (interprocedural stack survival, type recovery) and *perf* (the CodeQL
CFG query) on a minority of cutting-edge AVM contracts — not faithfulness.

Reproduce: `python -m tools.behavioral_lift.fetch_mainnet /tmp/m && \
python -m tools.behavioral_lift.compare /tmp/m` (needs a localnet on :4001).
