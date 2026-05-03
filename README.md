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
cd teal/scripts
./create-extractor-pack.sh
cd ../..
```

### 3. Register Extractor for CodeQL

```bash
rm -rf .codeql-extractors
mkdir -p .codeql-extractors/teal
cp -R teal/extractor-pack/* .codeql-extractors/teal/
```

### 4. Create a CodeQL Database

```bash
codeql database create tests/projects/gen-dbs/my-db --overwrite -l teal -s tests/projects/teal-contracts/fee-validation --search-path "$(pwd)/.codeql-extractors"
```

### 5. Run a Query

**CLI:**
```bash
codeql query run teal/ql/lib/codeql/missingTxnFeeValidation.ql --database tests/projects/gen-dbs/my-db
```

**Or use the CodeQL VS Code extension** for an interactive UI experience.

---

## Running Tests

All tests require the extractor to be built and registered first (steps 2-3 above).

### Running Individual Queries

You can run any `.ql` query file against a database:

```bash
codeql query run teal/ql/lib/codeql/<query>.ql --database tests/projects/<db>
```

To export results to JSON, use `codeql bqrs decode --format=json`.

---

## Python Analysis Layer (WIP)

> ⚠️ **Work in progress.** APIs, module names, snapshot formats, and detector defaults are all subject to change. Use as a research surface, not a stable interface.

`python-analysis/` is a Python layer over the CodeQL substrate. Each module loads a CodeQL database via `teal_ssa.SSAProgram(db_path)` and exposes either an SSA-level helper or a specific detector built on top of it. Analyses run from regular Python — no QL eval each time once the per-DB cache (`~/.cache/teal-graphs/`) is warm.

### Modules

**Substrate** — load and reason about a single program.

| Module | Purpose |
| --- | --- |
| `teal_ssa.SSAProgram` | SSA representation of a built CodeQL DB. The foundation everything else consumes. |
| `teal_path_predicates.PathPredicateAnalysis` | Per-BB path predicates from branch / assert outcomes. Supports `entry_seeds` and `bb_seeds` for cross-contract injection. |
| `teal_stacksim` | Per-line concrete stack simulation. |
| `teal_ast`, `teal_graphs` | AST and CFG / dataflow graph helpers. |

**Detectors and reports.**

| Module | What it finds |
| --- | --- |
| `teal_auth_domination.AuthDominationDetector` | State-mutating ops not dominated by a recognised sender check. |
| `teal_nonunique_box_key.NonUniqueBoxKeyDetector` | Non-unique external fields (e.g. `AssetName`) flowing into a box key. Also exposes the generic `Source` / `Sink` / `FlowRule` taint framework. |
| `teal_inner_txn_report.InnerTxnReport` | Per-`itxn_submit` group dump: each txn's fields and possible operand values. |
| `teal_group_reasoning.analyze` | Group shape the contract forces on every approving exit (`Global.GroupSize == 2`, `gtxn[0].Receiver == ...`, etc.). |
| `teal_box_dataflow` | Box dataflow in three flavours: `detect_into_box_flows` (external → box write), `detect_out_of_box_flows` (box read → sensitive sink), `detect_correlated_flows` (end-to-end chain via syntactic key matching). |
| `teal_xcontract.XContractGraph` | Cross-contract analysis: identifies appcall itxns with a constant `ApplicationID` resolvable in a registry, runs path predicates on each callee with seeded args, computes approving-exit summaries, feeds them back into the caller's BB. Includes `cross_auth_findings` for auth-domination across the boundary. |

### Example: run a detector

```python
from teal_ssa import SSAProgram
from teal_auth_domination import AuthDominationDetector

prog = SSAProgram("tests/dbs/xgov-db")
for v in AuthDominationDetector(prog).detect():
    print(v.pretty())
```

### Example: cross-contract auth domination

```python
from teal_ssa import SSAProgram
from teal_xcontract import XContractGraph, cross_auth_findings, load_registry

registry = load_registry("path/to/registry.yml")  # AppID → DB path
caller = SSAProgram("path/to/caller-db")
graph = XContractGraph.build(caller, registry)
for f in cross_auth_findings(graph):
    print(f.violation.pretty())
```

The notebooks under `examples/` (`example.ipynb`, `example_xgov.ipynb`, `example_inner_txn_report.ipynb`, `example_box_key_detection.ipynb`, `example_path_predicates.ipynb`) walk through the same modules interactively.

### Snapshot test harness

`tests/test_python_analyses.py` runs every analysis against fixtures under `tests/python/<analysis>/[<case>/]db/` and diffs output against checked-in `expected.txt`. The dispatch routes by the top-level analysis directory name; `xcontract/` and `box_df/` use case-name prefixes for sub-flavours.

```bash
# Build any missing fixture DBs (idempotent; --force to rebuild all)
tests/python/build_dbs.sh

# Verify all snapshots
pytest tests/test_python_analyses.py -v

# Regenerate baselines after an intended behaviour change
UPDATE_SNAPSHOTS=1 pytest tests/test_python_analyses.py -v
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
cd teal/scripts
./create-extractor-pack.sh
```

This will rebuild the Rust extractor, regenerate `teal.dbscheme` and `TreeSitter.qll`, and move them into the correct folders.

---

Made with love.

If you're into this kind of stuff, check out [TEALFuzz]() — a custom fuzzer for TEAL programs that uses TealQL to aid in fuzzing campaign setup.
