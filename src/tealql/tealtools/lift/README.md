# lift — lift CodeQL TEAL back into Puya IR

A **decompiler**: it takes a compiled Algorand program (a CodeQL TEAL database),
reconstructs structure the assembler threw away — subroutines, a typed value graph,
scratch/frame variables — and lifts the stack-machine SSA into genuine
[`puya.ir.models`](https://github.com/algorandfoundation/puya), the same IR Puya
itself compiles from. From there you can render it, run Puya's own optimiser, or
lower it all the way back to TEAL.

```
CodeQL TEAL DB
  └─ SSAProgram(source)          tealql.tealtools.ssa — stack-machine TEAL in SSA form
       └─ lift(prog)             → pre_ir.Program   (the Puya-SHAPED working model)
            │  recover_types · transforms (phi prune, reused-slot store sink) · …
            └─ to_puya(prog)     → real puya.ir.models  (main, subroutines)
                 ├─ optimize()   Puya's own optimiser passes
                 ├─ render()     → Puya IR text
                 └─ → MIR → TEAL  (backend.lift_to_teal)
```

> All commands assume the repo root and `PYTHONPATH=src` (the `tealql`
> package lives under `src/`).

## Quickstart (CLI)

```bash
# Render a DB as real Puya IR (add --optimize to run Puya's optimiser first)
PYTHONPATH=src python -m tealql.tealtools.lift <contract.teal> [--optimize]

# User-input taint report (which attacker-controlled values reach sensitive sinks)
PYTHONPATH=src python -m tealql.tealtools.lift.taint <contract.teal>

# …the same, annotated inline on the rendered IR
PYTHONPATH=src python -m tealql.tealtools.lift.taint --render <contract.teal>
```

The input is a TEAL source path (a file, or a directory of `.teal` for a
multi-program artifact). CodeQL is no longer involved anywhere on this path.


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

## User-input taint (`taint.py`)

A first IR-layer dataflow analysis. It forward-propagates taint from the inputs an
attacker chooses at call time — `ApplicationArgs`, `LogicSigArgs` (`arg`/`args`),
`ItxnLastLog` — through the IR's value flow, **interprocedurally**, with **precise
scratch flow** (it consumes the low-layer `load_stores` reaching-def carried up
through `lifter.regs`, so a `load N` is tainted only by the stores that actually
reach it).

```python
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift.lift import _Lifter
from tealql.tealtools.lift.taint import (
    user_input_taint, tainted_sinks, taint_report, render_with_taint)

lf = _Lifter(SSAProgram("path/to/contract.teal")); lf.build()  # need the lifter,
                                                # for load_stores + the reg map
taint = user_input_taint(lf)        # {id(Register): frozenset(sources)}
flows = tainted_sinks(lf)           # [(sources, sink_op, immediates), …]
print(taint_report(lf, "name"))     # grouped, human-readable, with TEAL lines
print(render_with_taint(lf, "name"))# the IR with <== SOURCE/tainted/SINK inline
```

See `tests/behavioral_lift/taint_example.txt` for a sample report. Two honest
approximations: subroutine *result* taint is conservative (any tainted arg taints
the result), and the source set is the three families above.

## Module layout

| Module | Role |
| --- | --- |
| `pre_ir.py` | The Puya-**shaped** working model (`Register`/`Assignment`/`Phi`/blocks/terminators) the lift builds and annotates. |
| `lift.py` | `_Lifter`: SSA → `pre_ir`. Subroutine partitioning, frame/scratch/stack-shuffle resolution, constant + phi inlining. `lift(prog)` is the entry. |
| `type_recovery.py` | AVM type + phi recovery on the pre-IR (uses/defs/phi-args/state/calls to a fixpoint; reconciles mixed-type phi webs). |
| `transforms.py` | In-place structural rewrites: dead-phi pruning, cross-group phi isolation, and `sink_mixed_phi_scratch_stores` (the reused-slot fix). |
| `arc4_recovery.py` | ARC-4 encoded-type recovery (confident tier + a speculative side-channel). |
| `box_recovery.py` | Rebuild Box/BoxMap declarations from the box opcodes. |
| `fund_flow.py` | The IR tainted-fund-flow engine and its guard classification. |
| `summaries.py` | Bottom-up procedure summaries (also consumed by the avm-prover submodule). |
| `backend.py` | Carry the lowered IR down to TEAL again — `lift_to_teal`. |
| `_puya_compat.py` | The one place that pins puya's private/moving API surface. |
| `teal_const.py` | TEAL source / literal parsing — pure text helpers. |
| `to_puya_ir.py` | Lower the pre-IR to **real** `puya.ir.models`; `to_puya()`, `render()`, `optimize()`. |
| `taint.py` | User-input taint analysis over the lifted IR (+ report and inline-render). |
| `__main__.py` | CLI entry — render a contract as Puya IR. |

## Status

Work-in-progress, but validated against reality:

- **Behaviour:** `tests/behavioral_lift/` lifts real mainnet TEAL → recompiles →
  dryruns original vs recompiled on a localnet. ~240 contracts across mainnet eras;
  every contract that lifts is behaviourally faithful.
- **Structure:** `tests/test_lift_semantics.py` (corpus = the Puya repo's compiled
  test-cases + 5 real DBs); run with `LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1`.

Known limits live as coverage/perf, not faithfulness: very large (≈59-subroutine)
contracts are slow in SSA construction, and a small residual of `?`-typed registers
(scratch loads of genuinely-reused slots) default harmlessly to `uint64`.
