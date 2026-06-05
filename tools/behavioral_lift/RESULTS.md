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
| mainnet (20)            | **20/20** | 380 | **0** |

**33/33 contracts that lift are behaviourally faithful** — across 695 dryrun
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

Reproduce: `python -m tools.behavioral_lift.fetch_mainnet /tmp/m && \
python -m tools.behavioral_lift.compare /tmp/m` (needs a localnet on :4001).
