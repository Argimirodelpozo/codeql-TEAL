# lift — lift TEAL back into Puya IR

A **decompiler**: it takes a compiled Algorand program (TEAL source, or the
disassembly of deployed bytecode), reconstructs structure the assembler threw
away — subroutines, a typed value graph, scratch/frame variables — and lifts the
stack-machine SSA into genuine
[`puya.ir.models`](https://github.com/algorandfoundation/puya), the same IR Puya
itself compiles from. From there you can render it, run Puya's own optimiser, or
lower it all the way back to TEAL.

```
contract.teal  (one AVM program; directory collections are projected per file)
  └─ SSAProgram(source)          tealql.tealtools.ssa — stack-machine TEAL in SSA form
       └─ lift(prog)             → pre_ir.Program   (the Puya-SHAPED working model)
            │  recover_types · transforms (phi prune, reused-slot store sink) · …
            └─ to_puya(prog)     → real puya.ir.models  (main, subroutines)
                 ├─ optimize()   Puya's own optimiser passes
                 ├─ render()     → Puya IR text
                 └─ → MIR → TEAL  (backend.lift_to_teal)
```

CodeQL is not involved anywhere on this path — it was dropped as a runtime and
test dependency, and the extractor floor underneath is pure Python
(`ast/parse.py` → `cfg/build.py` → `graph.load_graph`).

> All commands assume the repo root and `PYTHONPATH=src` (the `tealql`
> package lives under `src/`).

## Quickstart (CLI)

```bash
# Render a contract as real Puya IR (add --optimize to run Puya's optimiser first)
PYTHONPATH=src python -m tealql.tealtools.lift <contract.teal> [--optimize]

# User-input taint report (which attacker-controlled values reach sensitive sinks)
PYTHONPATH=src python -m tealql.tealtools.lift.taint <contract.teal>

# …the same, annotated inline on the rendered IR
PYTHONPATH=src python -m tealql.tealtools.lift.taint --render <contract.teal>
```

## Python API

```python
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift import lift, render

prog = SSAProgram("path/to/contract.teal")

ir   = lift(prog)                    # pre_ir.Program — the working model
text = render(prog)                  # real Puya IR as text
text = render(prog, optimize_ir=True)  # …after Puya's optimiser
```

Lower to **real** `puya.ir.models` and optimise:

```python
from tealql.tealtools.lift import to_puya_ir

main, subs = to_puya_ir.to_puya(prog)        # genuine puya.ir.models
to_puya_ir.optimize([main, *subs])           # Puya's optimiser passes
```

Recompile all the way **back to TEAL** (used by the behavioural test):

```python
from tealql.tealtools.lift import lift_to_teal
teal = lift_to_teal("path/to/contract.teal")  # TEAL text, re-assemblable
```

`build_lifter(prog, file=None)` returns (and caches) the `_Lifter` itself, for
callers that need `load_stores` or register provenance — the taint API below,
and the `avm-prover` submodule. For a directory-backed `SSAProgram`, pass one of
`prog.source_files`; direct `lift(prog)` refuses to merge independent programs
under one synthetic main.

## What it refuses to guess, and why

The representation aims to be **total and honest**: build for any legal TEAL, and
never assert a value it cannot justify. Three deliberate refusals implement that,
and each one replaced something that used to be silently wrong.

- **`SSAProgram(...)` is strict by default.** An unparsed span raises
  `TealParseError`; an opcode this build cannot model raises
  `UnknownOpcodeError` — it would otherwise get a `(0, 0)` stack effect and put
  every later value in the wrong slot. The CLI and `security.scan` pass
  `strict=False` because they surface partiality to the user themselves.
- **A callee that consumes the CALLER's stack** — legal TEAL: the AVM bounds
  `frame_dig`/`frame_bury` to the frame, but places no such bound on plain stack
  ops, so a `cover`/`uncover`/dig can reach underneath — leaves those caller
  slots `pre_ir.Undefined` rather than the stale pre-call value. Asserting the
  stale value inverted a program's outcome against a live AVM.
- **`Undefined` is TOP, never clean.** Both taint fixpoints seed
  `taint.UNKNOWN_SOURCE` for it and the sink scan counts it as a source, so an
  unresolved value reads as possibly-attacker-controlled. Treating it as clean is
  the silent false-negative shape this codebase has had to fix more than once.

Separately, a **legacy (non-`proto`) sub whose `retsub` sites leave different
stack depths is not a function** — no single `(nargs, nret)` describes it. The
lifter gives guarded cases one body copy per call site, turning the call back
into the jump it really is. Shapes outside those guards are collected in
`_Lifter.not_function_shaped` and visibly degrade or refuse rather than claiming
a false signature.

## User-input taint (`taint.py`)

An IR-layer dataflow analysis. It forward-propagates taint from the inputs an
attacker chooses at call time — `ApplicationArgs`, `LogicSigArgs` (`arg`/`args`),
`ItxnLastLog` — through the IR's value flow, **interprocedurally**, with **precise
scratch flow** (it consumes the low-layer `load_stores` reaching-def carried
through `lifter.register_sources`, so frame values, aliases, and exact structural
clones are included and a `load N` is tainted only by stores that actually reach
it).

```python
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift import build_lifter
from tealql.tealtools.lift.taint import (
    user_input_taint, tainted_sinks, taint_report, render_with_taint)

lf = build_lifter(SSAProgram("path/to/contract.teal"))  # need the lifter, for
                                                # load_stores + the reg map
taint = user_input_taint(lf)        # {id(Register): frozenset(sources)}
flows = tainted_sinks(lf)           # [(sources, sink_op, immediates), …]
print(taint_report(lf, "name"))     # grouped, human-readable, with TEAL lines
print(render_with_taint(lf, "name"))# the IR with <== SOURCE/tainted/SINK inline
```

See `tests/behavioral_lift/taint_example.txt` for a sample report. Two honest
approximations: subroutine *result* taint is conservative (any tainted argument
taints the result), and the source set is the three families above.

## Module layout

| Module | Role |
| --- | --- |
| `pre_ir.py` | The Puya-**shaped** working model (`Register`/`Assignment`/`Phi`/blocks/terminators), shared traversals, and post-transform structural validator. |
| `lift.py` | `_Lifter`: SSA → `pre_ir`. Subroutine partitioning, arity inference, `_resim` (the per-routine stack re-simulation every emitted operand comes from), frame/scratch/stack-shuffle resolution, constant + phi inlining. `lift(prog)` is the entry. |
| `type_recovery.py` | AVM type + phi recovery on the pre-IR (`recover_types`: uses/defs/phi-args/state/calls to a fixpoint; reconciles mixed-type phi webs). A langspec operand POSITION outranks a default or a seed — for registers, constants, unset `?` values and phi webs alike. |
| `transforms.py` | In-place structural rewrites: dead-phi pruning, cross-group phi isolation, `materialize_phi_consts`, and `sink_mixed_phi_scratch_stores` (the reused-slot fix). |
| `arc4_recovery.py` | ARC-4 encoded-type recovery (confident tier + a speculative side-channel). |
| `box_recovery.py` | Rebuild Box/BoxMap declarations from the box opcodes. |
| `fund_flow.py` | The IR tainted-fund-flow engine and its guard classification (dominating *and* post-dominating asserts, callee parameter/sender summaries). |
| `summaries.py` | Bottom-up procedure summaries (also consumed by the avm-prover submodule). |
| `backend.py` | Carry the lowered IR down to TEAL again — `lift_to_teal`. |
| `_puya_compat.py` | The one place that pins puya's private/moving API surface. |
| `teal_const.py` | TEAL source / literal parsing — pure text helpers. |
| `to_puya_ir.py` | Lower the pre-IR to **real** `puya.ir.models`; `to_puya()`, `render()`, `optimize()`. |
| `taint.py` | User-input taint analysis over the lifted IR (+ report and inline-render). |
| `__main__.py` | CLI entry — render a contract as Puya IR. |

## Status

Validated against reality on three independent axes:

- **Behaviour** — `tests/behavioral_lift/` lifts real mainnet TEAL, recompiles
  it, and dryruns original vs recompiled on a live localnet. Across ~240
  contracts spanning every mainnet era, the differential found exactly one
  behavioural divergence (found, fixed, pinned); every contract that lifts is
  behaviourally faithful. `tests/behavioral_lift/RESULTS.md` has the batches.
  Script-only — it needs algod on `http://localhost:4001`.
- **Structure** — `tests/test_lift_semantics.py`, corpus = the Puya repo's own
  compiled test-cases plus the real contracts in `tests/contracts/`. Run with
  `LIFT_SEMANTICS_CORPUS=1`, and `LIFT_SEMANTICS_BACKEND=1` for the Tier-3
  backend lowering.
- **Puya's own validator** — `to_puya(..., diagnostics=…)` captures the errors
  puya *logs* rather than raises. Zero, across the 231 distinct mainnet probes
  and every corpus contract, so `_KNOWN_PUYA_REPORTED` is an EMPTY pin: a name
  may only go back in with evidence, and the test fails on a stale entry too.

Coverage and cost, measured on the 231 distinct mainnet probes: **231/231 lift**,
101s for the whole set. The largest real contracts (~4.8k lines, 100
subroutines) take a few seconds each; the old "very large contracts are slow in
SSA construction" limit is gone.

Two known limits remain, neither of them a faithfulness gap in the decompiled
view:

- **A dead panicking op survives the lift but not the round-trip.** `+` overflow
  and `/` by zero PANIC on the AVM, so discarding the result does not make the op
  unobservable — and the lift does emit it. But puya's optimiser, which
  `lift_to_teal` runs afterwards, treats arithmetic as pure and deletes it, so a
  dead overflow recompiles to a program that approves where the original rejects
  (measured: 10 of 10 dryrun inputs). It is a mismatch of assumptions — puya's
  frontend guarantees arithmetic cannot panic, decompiled TEAL guarantees
  nothing. Pinned by `test_a_panicking_op_survives_into_the_pre_ir_even_when_dead`
  so that a regression dropping the op from the IR cannot hide behind the
  optimiser doing it anyway.
- **~0.5% of emitted registers stay `?`-typed** (0.52% over 40 probes) — scratch
  loads of genuinely reused slots — and default to `uint64` at lowering.
