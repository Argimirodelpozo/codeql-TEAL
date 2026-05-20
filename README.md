# TealQL

TealQL is an SAST powered by GitHub Advanced Security's CodeQL, bringing the latest in Static Analysis tooling to the Algorand Virtual Machine's native language.

## Quick Start (macOS)

### 1. Clone the Repository

```bash
git clone https://github.com/Argimirodelpozo/codeql-TEAL.git
cd codeql-TEAL
```

### 2. Build the TEAL Extractor

The script handles dependency linking and permissions automatically:

```bash
cd codeql-backend/teal/scripts
./create-extractor-pack.sh
cd ../..
```

### 3. Register Extractor for CodeQL

```bash
rm -rf .codeql-extractors
mkdir -p .codeql-extractors/teal
cp -R codeql-backend/teal/extractor-pack/* .codeql-extractors/teal/
```

### 4. Create a CodeQL Database

Pick any directory containing TEAL source as the snapshot input. The example below uses one of the bundled fixtures:

```bash
codeql database create /tmp/my-db --overwrite -l teal -s tests/tealtools/auth_domination/vuln --search-path "$(pwd)/.codeql-extractors"
```

### 5. Run a Query

**CLI:**
```bash
codeql query run codeql-backend/teal/ql/lib/codeql/missingTxnFeeValidation.ql --database /tmp/my-db
```

**Or use the CodeQL VS Code extension** for an interactive UI experience.

---

## Running Tests

All tests require the extractor to be built and registered first (steps 2-3 above).

### CodeQL Backend Tests

Native CodeQL tests covering the QL libraries (`codeql-backend/teal/ql/lib/codeql/...`), the tealtools queries (`analysis/tealtools/queries/...`), and the sec-guide detection suite (`security/detections/...`). Each test is a directory with a `prog.teal` (or other `.teal`) source plus a `test.ql` (focused unit test) or `test.qlref` (invokes a production query) and a checked-in `*.expected` output. The runner builds a DB from the source, runs the query, and diffs against expected. Wrapped in pytest so it shares the same workflow as the tealtools tests.

```bash
# Verify every backend test
pytest tests/test_codeql_backend.py -v

# Regenerate every .expected (use after intentional QL behaviour change)
UPDATE_SNAPSHOTS=1 pytest tests/test_codeql_backend.py
```

Discovery walks two roots — `tests/codeql/` and `security/detections/` — picking up any `.ql` / `.qlref` whose sibling `.expected` exists. The test pack at `tests/codeql/qlpack.yml` declares dependencies on `argimirodelpozo/teal-all` and `argimirodelpozo/tealtools` so `.qlref`s pointing at production queries resolve. First cold run after a QL change takes ~25 min (cache invalidates globally); subsequent runs are fast.

### Running Individual Queries

You can run any `.ql` query file against a database:

```bash
codeql query run codeql-backend/teal/ql/lib/codeql/<query>.ql --database <path/to/db>
```

To export results to JSON, use `codeql bqrs decode --format=json`.

---

## Python Analysis Layer (WIP)

> ⚠️ **Work in progress.** APIs, module names, snapshot formats, and detector defaults are all subject to change. Use as a research surface, not a stable interface.

`analysis/tealtools/` is a Python package (installed as `tealtools`) over the CodeQL substrate. Each submodule loads a CodeQL database via `tealtools.SSAProgram(db_path)` and exposes either an SSA-level helper or a specific detector. Analyses run from regular Python — no QL eval each time once the per-DB cache (`~/.cache/teal-graphs/`) is warm.

### Install

```bash
pip install -e .
```

That puts a `tealql` binary on `$PATH`. `python -m cli` works as a fallback.

### CLI

Every analysis subcommand takes a single `<target>` — a `.teal` file, a directory of `.teal` files, or an existing CodeQL DB. When the target is raw source, a DB is built on the fly and cached under `~/.cache/tealql/dbs/` (override via `$TEALQL_DB_CACHE`).

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
| `--db-cache DIR` | override the auto-built-DB cache root |
| `--force-rebuild` | rebuild the DB even if a cached one exists |
| `-v`, `--verbose` | print DB-build progress to stderr |

For raw CodeQL operations there is a `debug` namespace:

```bash
tealql debug query <ql-file> <target>     # codeql query run, with target resolution
tealql debug db    <target>                # resolve + print the DB path
tealql debug cache {info|clear}            # inspect or clear the DB cache
```

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
| | `propagate_byte_lengths` | exact `TealType.byte_length` on bytes producers (`itob` → 8, `concat` → sum, `sha256` → 32, …) plus inverse `byte_length_range` constraints from `btoi` / `getbyte` / `extract_uint*` / etc. on their bytes inputs |
| | `propagate_bytemath_ranges` | bigint `TealType.int_value_range` (Python arbitrary-precision ints) over `b+` / `b-` / `b*` / `b/` / `b%` with the `itob` / `btoi` bridge between uint64 and bytes-bigint value spaces |
| **C. Structural lowering** | `propagate_stack_shuffles` | copy-propagate pure shuffles (`dup`, `swap`, `frame_dig`, …); mark them `shuffled=True` so they render as `// …` comments |
| | `cleanup_unused_ssavars` | drop side-effect-free Assignments whose every output is dead (typical victims: duplicate reader Assignments from phase A) |
| | `eliminate_dead_constants` | inline literal constants into consumers; drop now-orphan SSAVars / Phis / Assignments |
| | `materialize_phis` | out-of-SSA lowering — each live phi becomes a `mat_phi_k` with a copy assignment at every contributing leaf's def site |

Each pass is idempotent — running `run_all_passes` twice is a
no-op the second time. The per-pass implementations live in
`analysis/tealtools/passes/<name>.py`; the substrate
(`analysis/tealtools/ssa.py`) carries only a thin lazy-import bridge
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
| `tealtools.ssa.SSAProgram` | SSA representation of a built CodeQL DB. The foundation everything else consumes. |
| `tealtools.path_predicates.PathPredicateAnalysis` | Per-BB path predicates from branch / assert outcomes. Supports `entry_seeds` and `bb_seeds` for cross-contract injection. |
| `tealtools.stacksim` | Per-line concrete stack simulation. |
| `tealtools.ast`, `tealtools.graphs` | AST and CFG / dataflow graph helpers. |

**Detectors and reports.**

| Module | What it finds |
| --- | --- |
| `tealtools.auth_domination.AuthDominationDetector` | State-mutating ops not dominated by a recognised sender check. |
| `tealtools.detections.NonUniqueBoxKeyDetector` | Non-unique external fields (e.g. `AssetName`) flowing into a box key. Registered as the `box-key` detection — run via `tealql detections --detector box-key`. |
| `tealtools.inner_txn_report.InnerTxnReport` | Per-`itxn_submit` group dump: each txn's fields and possible operand values. |
| `tealtools.group_reasoning.analyze` | Group shape the contract forces on every approving exit (`Global.GroupSize == 2`, `gtxn[0].Receiver == ...`, etc.). |
| `tealtools.box_dataflow` | Box dataflow in three flavours: `detect_into_box_flows` (external → box write), `detect_out_of_box_flows` (box read → sensitive sink), `detect_correlated_flows` (end-to-end chain via syntactic key matching). |
| `tealtools.xcontract.XContractGraph` | Cross-contract analysis: identifies appcall itxns with a constant `ApplicationID` resolvable in a registry, runs path predicates on each callee with seeded args, computes approving-exit summaries, feeds them back into the caller's BB. Includes `cross_auth_findings` for auth-domination across the boundary. |
| `tealtools.cost_analysis` | Per-line opcode-budget cost with worst-case path accumulation; loops report `unbounded`. |
| `tealtools.predicate_aware.filter_validated` | Wraps a taint detector — suppresses violations whose sink operand is constrained by a dominating path predicate. |

### Example: run a detector

```python
from tealtools import SSAProgram, AuthDominationDetector

prog = SSAProgram("tests/dbs/xgov-db")
for v in AuthDominationDetector(prog).detect():
    print(v.pretty())
```

### Example: cross-contract auth domination

```python
from tealtools import SSAProgram, XContractGraph, cross_auth_findings, load_registry

registry = load_registry("path/to/registry.yml")  # AppID → DB path
caller = SSAProgram("path/to/caller-db")
graph = XContractGraph.build(caller, registry)
for f in cross_auth_findings(graph):
    print(f.violation.pretty())
```

The notebooks under `analysis/tealtools/interactive-examples/` (`example.ipynb`, `example_xgov.ipynb`, `example_inner_txn_report.ipynb`, `example_box_key_detection.ipynb`, `example_path_predicates.ipynb`) walk through the same modules interactively.

### Snapshot test harness

`tests/test_python_analyses.py` runs every analysis against fixtures under `tests/tealtools/<analysis>/[<case>/]db/` and diffs output against checked-in `expected.txt`. The dispatch routes by the top-level analysis directory name; `xcontract/` and `box_df/` use case-name prefixes for sub-flavours.

Missing fixture DBs are built automatically by a session-start hook in `tests/conftest.py` — no separate build step. Manual control:

```bash
# Verify all snapshots (auto-builds any missing DB first)
pytest tests/test_python_analyses.py -v

# Regenerate baselines after an intended behaviour change
UPDATE_SNAPSHOTS=1 pytest tests/test_python_analyses.py -v

# Force-rebuild every DB (mostly for debugging extractor changes)
python tests/build_dbs.py --force
```

First run on a cold cache evaluates the underlying CodeQL queries per fixture (~25min for the full suite); subsequent runs are fast (seconds).

---

## Prerequisites

- [CodeQL CLI](https://github.com/github/codeql-cli-binaries) (`codeql` on PATH)
- Rust toolchain (for building the extractor)
- Python 3 with `pytest` (for running tests)

## Features Coming Soon

## How to Contribute

## Rebuilding Extractors

When encountering parsing errors, a grammar update is probably needed.

1. Fix the appropriate rule in the grammar
2. Commit and push to main
3. Rebuild:

```bash
cd codeql-backend/teal/scripts
./create-extractor-pack.sh
```

This will rebuild the Rust extractor, regenerate `teal.dbscheme` and `TreeSitter.qll`, and move them into the correct folders.

---

Made with love.

If you're into this kind of stuff, check out [TEALFuzz]() — a custom fuzzer for TEAL programs that uses TealQL to aid in fuzzing campaign setup.
