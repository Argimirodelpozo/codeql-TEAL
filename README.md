# TealQL

TealQL is a static-analysis toolkit for [TEAL](https://developer.algorand.org/docs/get-details/dapps/avm/teal/), the Algorand Virtual Machine's native language. It reconstructs typed SSA from raw TEAL source and runs detectors, reports, and a Puya-IR lift on top of it.

It began life on GitHub CodeQL; the analysis layer is now **pure Python** — there is no CodeQL CLI, extractor, or database to build. You point it at `.teal` source and it does the rest.

## Quick Start

### Clone & install

```bash
git clone https://github.com/Argimirodelpozo/codeql-TEAL.git
cd codeql-TEAL
pip install -e .
```

That puts a `tealql` binary on `$PATH`. `python -m cli` works as a fallback.

### Run an analysis

Every subcommand takes a single `<target>` — a `.teal` file, or a directory of `.teal` files. The pipeline (source → graph → SSA → analysis) reconstructs everything straight from that source; there is nothing to build or cache.

```bash
tealql auth tests/tealtools/auth_domination/vuln/prog.teal
```

---

## Python Analysis Layer (WIP)

> ⚠️ **Work in progress.** APIs, module names, snapshot formats, and detector defaults are all subject to change. Use as a research surface, not a stable interface.

`src/analysis/tealtools/` is a Python package (installed as `tealtools`). Each submodule loads a program via `tealtools.SSAProgram(<source>)` and exposes either an SSA-level helper or a specific detector. `<source>` is a `.teal` file or a directory of them; the graph and SSA are rebuilt in-process (pure Python, milliseconds).

### CLI

```bash
tealql --help

# Detectors (emit findings; exit code 1 on any finding)
tealql auth             <target>
tealql box-df           <target> --flavour {into|out|correlated}
tealql detections       <target> {--detector NAME | --all | --list} [--mode app|logicsig]
tealql detections-scan  <root>   [--config rules.yml] [--mode-config modes.yml]

# Reports
tealql itxn-report     <target>
tealql group-shape     <target>
tealql group-layout    <target>
tealql cost            <target>
tealql path-predicates <target>
tealql cfg             <target> [--file F] [--skeleton]
tealql xcontract       <target> --registry <yml>

# Annotated SSA dump (runs every pass and prints functional form)
tealql functional      <target> [--show-ranges] [--show-bytes] [--by-block]

# Everything at once (all detectors + all reports)
tealql all             <target>
```

Common flags accepted by every analysis subcommand:

| Flag | Effect |
| --- | --- |
| `--json` | emit JSON instead of text |
| `-v` / `-vv` | progress logging to stderr — `-v` for INFO milestones (target resolution, SSA build, pass pipeline, per-detection counts), `-vv` adds DEBUG per-pass timings |

### Pipeline

Every analysis builds on a canonical pass pipeline orchestrated by
`tealtools.passes.run_all_passes`. Three phases run in order;
`tealql functional` is the most convenient way to see the
fully-annotated result.

| Phase | Pass | What it adds |
| --- | --- | --- |
| **A. Value flow** | `propagate_constants` | `const_value` on literal-pushing producers |
| | `propagate_scratch_constants` | same, across `store` / `load` for scratch slots |
| | `propagate_inputs` | unify execution-stable reads (`txn` / `gtxn` / `global` / `arg`) to one canonical SSAVar per (op, immediates, stack-key) |
| | `propagate_scratch_values` | forward a `load N` to its single may-store source SSAVar when every may-influencing store agrees |
| **B. Analytical annotation** | `propagate_ranges` | uint64 `IntRange` from op tables (boolean comparisons, `getbyte`, txn enum fields, …) + phi union |
| | `propagate_range_arithmetic` | composes ranges through `+` / `-` / `*` / `/` / `%` with phi re-union |
| | `propagate_assert_ranges` | tightens ranges from the contract's own `assert` guards (flow-sensitive, dominance-checked) |
| | `propagate_byte_lengths` | exact `TealType.byte_length` on bytes producers (`itob` → 8, `concat` → sum, `sha256` → 32, …) plus inverse `byte_length_range` constraints from `btoi` / `getbyte` / `extract_uint*` / etc. on their bytes inputs |
| | `propagate_bytemath_ranges` | bigint `TealType.int_value_range` (Python arbitrary-precision ints) over `b+` / `b-` / `b*` / `b/` / `b%` with the `itob` / `btoi` bridge between uint64 and bytes-bigint value spaces |
| **C. Structural cleanup** | `propagate_stack_shuffles` | copy-propagate pure shuffles (`dup`, `swap`, `frame_dig`, …); mark them `shuffled=True` so they render as `// …` comments |
| | `cleanup_unused_ssavars` | drop side-effect-free Assignments whose every output is dead (typical victims: duplicate reader Assignments from phase A) |

(Out-of-SSA lowering is no longer part of this pipeline — the Puya-IR lift does its own via `tealtools.block_args`; the functional dump renders live phis in phi form.)

Each pass is idempotent — running `run_all_passes` twice is a
no-op the second time. The per-pass implementations live in
`src/analysis/tealtools/passes/<name>.py`; the substrate
(`src/analysis/tealtools/ssa/`) carries only a thin lazy-import bridge
method per pass (`SSAProgram.propagate_*` / `cleanup_*`) so
analysis semantics stay out of the substrate.

Inline annotations rendered by `tealql functional`:

| Flag | Format | Source |
| --- | --- | --- |
| `--show-ranges` | `/*[V<=hi]*/` after a uint64 SSAVar | `propagate_ranges`, `propagate_range_arithmetic` |
| `--show-bytes` | `/*len=N*/`, `/*N<=len<=M*/`, `/*val=…*/`, `/*val∈[lo..hi]*/` after a bytes SSAVar | `propagate_byte_lengths`, `propagate_bytemath_ranges` |

### Modules

**Substrate** — load and reason about a single program.

| Module | Purpose |
| --- | --- |
| `tealtools.ssa.SSAProgram` | SSA representation reconstructed from TEAL source. The foundation everything else consumes. |
| `tealtools.path_predicates.PathPredicateAnalysis` | Per-BB path predicates from branch / assert outcomes. Supports `entry_seeds` and `bb_seeds` for cross-contract injection. |
| `tealtools.stacksim` | Per-line concrete stack simulation. |
| `tealtools.ast`, `tealtools.graphs` | AST and CFG / dataflow graph helpers. |

**Detectors and reports.**

| Module | What it finds |
| --- | --- |
| `tealtools.auth_domination.AuthDominationDetector` | State-mutating ops not dominated by a recognised sender check. |
| `security.NonUniqueBoxKeyDetector` | Non-unique external fields (e.g. `AssetName`) flowing into a box key. Registered as the `box-key` detection — run via `tealql detections --detector box-key`. |
| `tealtools.inner_txn_report.InnerTxnReport` | Per-`itxn_submit` group dump: each txn's fields and possible operand values. |
| `tealtools.group_reasoning.analyze` | Group shape the contract forces on every approving exit (`Global.GroupSize == 2`, `gtxn[0].Receiver == ...`, etc.). |
| `tealtools.dataflow.box` | Box dataflow in three flavours: `detect_into_box_flows` (external → box write), `detect_out_of_box_flows` (box read → sensitive sink), `detect_correlated_flows` (end-to-end chain via syntactic key matching). |
| `tealtools.xcontract.XContractGraph` | Cross-contract analysis: identifies appcall itxns with a constant `ApplicationID` resolvable in a registry, runs path predicates on each callee with seeded args, computes approving-exit summaries, feeds them back into the caller's BB. Includes `cross_auth_findings` for auth-domination across the boundary. |
| `tealtools.cost_analysis` | Per-line opcode-budget cost with worst-case path accumulation; loops report `unbounded`. |
| `tealtools.dataflow.predicate_aware.filter_validated` | Wraps a taint detector — suppresses violations whose sink operand is constrained by a dominating path predicate. |

### Example: run a detector

```python
from tealtools import SSAProgram, AuthDominationDetector

prog = SSAProgram("tests/tealtools/auth_domination/vuln/prog.teal")
for v in AuthDominationDetector(prog).detect():
    print(v.pretty())
```

### Example: cross-contract auth domination

```python
from tealtools import SSAProgram, XContractGraph, cross_auth_findings, load_registry

registry = load_registry("path/to/registry.yml")  # AppID → .teal path
caller = SSAProgram("path/to/caller.teal")
graph = XContractGraph.build(caller, registry)
for f in cross_auth_findings(graph):
    print(f.violation.pretty())
```

The notebooks under `playground/interactive-examples/` (`example.ipynb`, `example_xgov.ipynb`, `example_inner_txn_report.ipynb`, `example_box_key_detection.ipynb`, `example_path_predicates.ipynb`) walk through the same modules interactively.

### Puya-IR lift

`tealtools.lift` lifts the reconstructed SSA into genuine [Puya](https://github.com/algorandfoundation/puya) IR (`puya.ir.models`), validating and optimising it with Puya's own passes:

```bash
python -m tealtools.lift <teal-source> [--optimize]
```

---

## Running Tests

```bash
pip install -e .
pytest tests/ -q
```

The suite is pure Python — no CodeQL, JVM, or network needed for the core tests.

### Snapshot harness

`tests/test_python_analyses.py` runs every analysis against fixtures under `tests/tealtools/<analysis>/[<case>/]db/` (each holds a `.teal` source plus a committed `graph_golden.txt`) and diffs output against checked-in `expected.txt`. The dispatch routes by the top-level analysis directory name; `xcontract/` and `box_df/` use case-name prefixes for sub-flavours.

```bash
# Verify all snapshots
pytest tests/test_python_analyses.py -v

# Regenerate baselines after an intended behaviour change
UPDATE_SNAPSHOTS=1 pytest tests/test_python_analyses.py -v
```

### Graph golden fixtures

`tests/test_graph_golden.py` pins the pure-Python graph producers (`nodes` / `cfgEdges` / `basicBlocks`) to a committed `graph_golden.txt` per fixture. Regenerate after an intentional change to the producers:

```bash
python -m tests.gen_graph_golden
```

---

## Prerequisites

- Python 3 with the package installed (`pip install -e .` pulls in the runtime deps).
- `pytest` for the test suite.

---

Made with love.

If you're into this kind of stuff, check out [TEALFuzz](https://github.com/Argimirodelpozo/TEALFuzz) — a custom fuzzer for TEAL programs that uses TealQL to aid in fuzzing campaign setup.
