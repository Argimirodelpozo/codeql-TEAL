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

Native CodeQL tests covering the QL libraries (`codeql-backend/teal/ql/lib/codeql/...`), the tealtools queries (`tealtools/queries/...`), and the sec-guide detection suite (`sec-guide-detections/...`). Each test is a directory with a `prog.teal` (or other `.teal`) source plus a `test.ql` (focused unit test) or `test.qlref` (invokes a production query) and a checked-in `*.expected` output. The runner builds a DB from the source, runs the query, and diffs against expected. Wrapped in pytest so it shares the same workflow as the tealtools tests.

```bash
# Verify every backend test
pytest tests/test_codeql_backend.py -v

# Regenerate every .expected (use after intentional QL behaviour change)
UPDATE_SNAPSHOTS=1 pytest tests/test_codeql_backend.py
```

Discovery walks two roots — `tests/codeql/` and `sec-guide-detections/` — picking up any `.ql` / `.qlref` whose sibling `.expected` exists. The test pack at `tests/codeql/qlpack.yml` declares dependencies on `argimirodelpozo/teal-all` and `argimirodelpozo/tealtools` so `.qlref`s pointing at production queries resolve. First cold run after a QL change takes ~25 min (cache invalidates globally); subsequent runs are fast.

### Running Individual Queries

You can run any `.ql` query file against a database:

```bash
codeql query run codeql-backend/teal/ql/lib/codeql/<query>.ql --database <path/to/db>
```

To export results to JSON, use `codeql bqrs decode --format=json`.

---

## Python Analysis Layer (WIP)

> ⚠️ **Work in progress.** APIs, module names, snapshot formats, and detector defaults are all subject to change. Use as a research surface, not a stable interface.

`tealtools/` is a Python package over the CodeQL substrate. Each submodule loads a CodeQL database via `tealtools.SSAProgram(db_path)` and exposes either an SSA-level helper or a specific detector. Analyses run from regular Python — no QL eval each time once the per-DB cache (`~/.cache/teal-graphs/`) is warm.

### Install

```bash
pip install -e .
```

That puts a `tealql` binary on `$PATH`. `python -m tealtools` continues to work as a fallback.

### CLI

Every analysis subcommand takes a single `<target>` — a `.teal` file, a directory of `.teal` files, or an existing CodeQL DB. When the target is raw source, a DB is built on the fly and cached under `~/.cache/tealql/dbs/` (override via `$TEALQL_DB_CACHE`).

```bash
tealql --help

# Detectors (emit findings; exit code 1 on any finding)
tealql auth            <target>
tealql box-key         <target>
tealql box-df          <target> --flavour {into|out|correlated}
tealql sec-guide       <target> {--detector NAME | --all}
tealql sec-guide-scan  <root>   [--config rules.yml]

# Reports
tealql itxn-report     <target>
tealql group-shape     <target>
tealql cost            <target>
tealql path-predicates <target>
tealql cfg             <target> [--file F] [--skeleton]
tealql xcontract       <target> --registry <yml>

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
| `tealtools.nonunique_box_key.NonUniqueBoxKeyDetector` | Non-unique external fields (e.g. `AssetName`) flowing into a box key. Also exposes the generic `Source` / `Sink` / `FlowRule` taint framework. |
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

The notebooks under `tealtools/interactive-examples/` (`example.ipynb`, `example_xgov.ipynb`, `example_inner_txn_report.ipynb`, `example_box_key_detection.ipynb`, `example_path_predicates.ipynb`) walk through the same modules interactively.

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
