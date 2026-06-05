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
| 15 disassembled-mainnet (explorer, in-repo)      | **13/15** |
| 20 freshly-fetched mainnet apps (incl. Tinyman v2) | **20/20** |

The 2 explorer fails: a TEAL-optimiser explicit-check edge and a type-recovery
incompatible-assignment gap. The 20 mainnet apps span 170–2842 recompiled TEAL
lines (Tinyman v2 router 2842 lines -> 5509 bytes).

## Behaviour — execution on a live AVM

| corpus | behaviourally faithful | inputs (outcome-matched) | real divergences |
|--------|------------------------|--------------------------|------------------|
| explorer (13 that lift) | **13/13** | 315 | **0** |
| mainnet (20)            | **20/20** | 380 | **0** |

**33/33 contracts that lift are behaviourally faithful** — across 695 dryrun
inputs the recompiled program's approve/reject decision matches the original on
every one. 175 inputs differ only in the failure opcode (the recompiled program
uses `assert` where the original used `err`; both reject the transaction — a
benign decompile->recompile artifact, not a behaviour change).

Caveat: dryrun without on-chain state / foreign refs mostly exercises the
routing + guard paths (most inputs reject); it proves the lift never flips an
approve<->reject decision on the tested inputs, the safety property that matters
most. Deeper approval-path coverage needs contract-specific state setup.

Reproduce: `python -m tools.behavioral_lift.fetch_mainnet /tmp/m && \
python -m tools.behavioral_lift.compare /tmp/m` (needs a localnet on :4001).
