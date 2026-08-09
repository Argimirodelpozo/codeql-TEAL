# TealQL

TealQL is a static-analysis **and decompilation** toolkit for [TEAL](https://developer.algorand.org/docs/get-details/dapps/avm/teal/), the Algorand Virtual Machine's native language. It reconstructs typed SSA from raw TEAL source, lifts it to genuine [Puya](https://github.com/algorandfoundation/puya) IR, **recovers the ARC-4 and storage types that compilation erased**, and runs security detectors, reports, and type-driven audits on top.

It began life on GitHub CodeQL; the analysis layer is now **pure Python** — there is no CodeQL CLI, extractor, or database to build. You point it at `.teal` source and it does the rest.

## Quick Start

### Clone & install

Managed with [uv](https://docs.astral.sh/uv/) — `uv.lock` pins the exact
dependency tree (including the pinned tree-sitter-teal grammar commit and the
puya compiler internals the lift targets), so your environment matches CI:

```bash
git clone https://github.com/Argimirodelpozo/codeql-TEAL.git
cd codeql-TEAL
uv sync                          # core: parse + SSA + detectors (Python >= 3.12)
uv sync --extra lift             # + puyapy, for decompilation to real Puya IR / TEAL
uv run tealql --help             # run the CLI in the synced env
```

Prefer pip? It reads the same `pyproject.toml` (hatchling is the build backend):

```bash
pip install -e .                 # core
pip install -e '.[lift]'         # + lift extra
```

Either way you get a `tealql` binary (`uv run tealql …` or, with pip, on `$PATH`);
`python -m tealql.cli` is a fallback. The core install pulls everything the
analysis needs, including the
[tree-sitter-teal](https://github.com/Argimirodelpozo/tree-sitter-teal) grammar
(a pinned git dependency). The `lift` extra is only needed to lower programs to
genuine `puya.ir` — every detector, including the `ir-*` family, runs without it.

### Run an analysis

Every subcommand takes a single `<target>` — a `.teal` file, or a directory of `.teal` files. The pipeline (source → graph → SSA → analysis) reconstructs everything straight from that source; there is nothing to build or cache.

```bash
tealql auth tests/tealtools/auth_domination/vuln/prog.teal
```

---

## Architecture

A layered pipeline, every layer pure Python and reconstructed from the layer below — no database, no build step. A whole contract goes source → findings in milliseconds; the lift adds Puya's own optimisation passes on top.

```
TEAL source
  │   tree-sitter-teal grammar  →  AST + CFG            (pure-Python extractor, no CodeQL)
  ▼
Typed SSA                                               (Braun on-demand construction)
  │   immutable facts: constants · aliases · ranges · byte facts
  ├─────────────►  Detectors (36)  ──►  findings        (SSA-level + interprocedural `ir-*` family)
  │
  ▼   lift  (needs the `lift` extra: puyapy)
Genuine Puya IR   (puya.ir.models)                      validated + optimised by Puya's own passes
  │   type recovery  ·  storage-schema recovery
  ├─────────────►  Type-driven audits  (abi-audit, box-audit)
  └─────────────►  Decompilation output (recovered ARC-4 types, Box/BoxMap schema)
```

Subsystems, bottom to top:

- **Extractor & SSA.** A pinned [tree-sitter-teal](https://github.com/Argimirodelpozo/tree-sitter-teal) grammar parses source to an AST; a pure-Python extractor builds the CFG (basic blocks, control-flow + interprocedural `retsub` edges). SSA is reconstructed with **Braun on-demand construction** (minimal phis; a forward depth-cap tames the loop-slot spiral) — the substrate every layer above consumes.
- **Value analysis.** The canonical SSA is never rewritten for analysis. A revision-scoped `AnalysisContext` exposes immutable constants, value identities, uint64 ranges, byte lengths, and bigint ranges. Consumers that still need annotation-oriented SSA receive a cached, read-only derived normal form instead of mutating the graph shared by every detector. See [Analysis contexts](#analysis-contexts).
- **Detectors.** 36 registered detections (`tealql detections --list`), auto-discovered from `src/tealql/security/detections/`. Beyond the SSA-level detectors there is an interprocedural **`ir-*` family** that runs on the lifted IR, where guard-dominance across `callsub` is precise; each is scored against a ground-truth corpus (see [Detector precision / recall](#detector-precision--recall)).
- **The lift.** `tealql.tealtools.lift` lowers the SSA into *genuine* `puya.ir.models`, validated and optimised by Puya's own passes — not a re-implementation. It is behaviourally verified: ~900 real mainnet contracts (v2–v11) lift → recompile → dryrun **identically to their deployed bytecode** (`tests/behavioral_lift/`, `tests/mainnet-random-probes/`).
- **Type recovery** (on the lifted IR — types erased by compilation, recovered from byte idioms). Two tiers, kept separate: a **confident** tier that refines the real `ir_type` (langspec-forward + usage-backward `account`), proven annotation-only / TEAL-neutral by `tests/test_recovery_neutral.py`; and a **speculative** side-channel of ARC-4 `String` / dynamic + static arrays / structs / addresses, each tagged fully-vs-somewhat confident, that never touches codegen.
- **Storage-schema recovery.** Reconstructs Puya's own `ContractState` model — global / local / box, single keys and maps, with recovered key/value types including **composite tuple keys** (e.g. a per-holder balance box keyed `(address, uint64)`) — resolving keys built in a caller and passed into a helper **interprocedurally**. That ARC-56 schema is not in the deployed bytecode.
- **Type-driven audits.** `abi-audit` and `box-audit` consume the recovered types to flag caller-controlled funds recipients and cross-user storage access (see [Type recovery & decompilation](#type-recovery--decompilation-needs-the-lift-extra)).

**Verification philosophy.** Nothing is trusted on structural acceptance alone: the lift is gated by real-execution faithfulness (localnet dryruns), type recovery by a snapshot-in-place **neutrality gate** (recovery must be annotation-only), detectors by a **precision/recall benchmark**, and the graph/analysis producers by committed **golden snapshots**.

---

## Python Analysis Layer (WIP)

> ⚠️ **Work in progress.** APIs, module names, snapshot formats, and detector defaults are all subject to change. Use as a research surface, not a stable interface.

`src/tealql/tealtools/` is a Python package (installed as `tealql.tealtools`). Each submodule loads a program via `tealql.tealtools.SSAProgram(<source>)` and exposes either an SSA-level helper or a specific detector. `<source>` is a `.teal` file or a directory of them; the graph and SSA are rebuilt in-process (pure Python, milliseconds).

### CLI

```bash
tealql --help

# Detectors (emit findings; exit code 1 on any finding)
tealql auth             <target>
tealql box-df           <target> --flavour {into|out|correlated}
tealql detections       <target> {--detector NAME | --all | --list} [--mode app|logicsig]
tealql detections-scan  <root>   [--config rules.yml] [--mode-config modes.yml]
tealql group-taint      <member.teal>...   # cross-member taint over an atomic group (in group order)

# Type-recovery-driven audits (need the lift extra — puyapy; exit 1 on any finding)
tealql abi-audit        <target>   # caller-supplied arc4.Address paid to a fund/asset sink unguarded
tealql box-audit        <target>   # caller-supplied address-keyed BoxMap not bound to txn Sender (cross-user access)

# Reports
tealql itxn-report     <target>
tealql group-shape     <target>
tealql group-layout    <target>
tealql path-predicates <target>
tealql cfg             <target> [--file F] [--skeleton]
tealql loops           <target> [--budget-mode auto|app|clear-state|logicsig]
                               [--app-calls N] [--inner-app-calls N] [--budget N]
tealql storage-schema  <target>   # reconstruct global/local/box keys + maps with recovered key/value types (needs lift)
tealql xcontract       <target> {--registry <yml> | --from-chain [--cache-dir D]} [--detections | --detector NAME]

# Annotated SSA dump (renders an isolated presentation normal form)
tealql functional      <target> [--show-ranges] [--show-bytes] [--by-block]

# Everything at once (all detectors + all reports)
tealql all             <target>
```

Common flags accepted by every analysis subcommand:

| Flag | Effect |
| --- | --- |
| `--json` | emit JSON instead of text |
| `-v` / `-vv` | progress logging to stderr — `-v` for INFO milestones (target resolution, SSA build, per-detection counts), `-vv` adds DEBUG analysis timings |

### Analysis contexts

`SSAProgram` is the canonical structural representation. Its assignments,
operands, phis, and canonical opcode stream do not change because a detector ran.
`prog.facts(...)` returns immutable facts keyed by stable SSA identities:

| Fact | Meaning |
| --- | --- |
| constant | a compile-time `Const`, including folding and must-agree scratch flow |
| alias | a proven identity across stable input reads, stack shuffles, or must-agree scratch loads |
| integer range | an unconditional uint64 `IntRange` from op seeds and arithmetic |
| `range_at(value, use)` | the range at one use after dominance-checked assertion refinement |
| type facts | exact/ranged byte lengths and arbitrary-precision bigint value ranges |

Facts are cached by program revision and domain; a broader cached fact set also
serves narrower queries. This makes detector order irrelevant without paying for
the same fixed point repeatedly.

Some older algorithms are easier to express over annotated operands. They call
`tealql.tealtools.analysis.derived_program` with one of three explicit profiles:

| Profile | Purpose |
| --- | --- |
| `VALUE` | constants, aliases, ranges, byte lengths, and bigint ranges |
| `GUARDED` | `VALUE` plus dominance-scoped assertion refinement |
| `PRESENTATION` | `GUARDED` plus dead pure-assignment cleanup for rendering |

These normal forms are revision-scoped, cached, and treated as read-only. The
canonical opcode stream is retained separately, so budget analysis and the IR
lift never price or execute a presentation-cleaned program. Out-of-SSA lowering
is likewise not part of value analysis; the Puya-IR lift lowers its pre-IR phis
directly.

Inline annotations rendered by `tealql functional`:

| Flag | Format | Source |
| --- | --- | --- |
| `--show-ranges` | `/*[V<=hi]*/` after a uint64 SSAVar | `propagate_ranges`, `propagate_range_arithmetic` |
| `--show-bytes` | `/*len=N*/`, `/*N<=len<=M*/`, `/*val=…*/`, `/*val∈[lo..hi]*/` after a bytes SSAVar | `propagate_byte_lengths`, `propagate_bytemath_ranges` |

### Modules

**Substrate** — load and reason about a single program.

| Module | Purpose |
| --- | --- |
| `tealql.tealtools.ssa.SSAProgram` | SSA representation reconstructed from TEAL source. The foundation everything else consumes. |
| `tealql.tealtools.path_predicates.PathPredicateAnalysis` | Per-BB path predicates from branch / assert outcomes. Supports `entry_seeds` and `bb_seeds` for cross-contract injection. |
| `tealql.tealtools.analysis` | Revision-scoped immutable `ValueFacts` and read-only derived SSA normal forms. |
| `tealql.tealtools.budget` | Version/mode-aware opcode-cost facts, reachable reducible and irreducible loops, minimum-cost reachability, method summaries, `OpcodeBudget` guard checks, and exhaustion review candidates. |
| `tealql.tealtools.ast`, `tealql.tealtools.graph`, `tealql.tealtools.viz` | AST layer, the source→graph loader, and DOT/SVG rendering. |

**Detectors and reports.**

| Module | What it finds |
| --- | --- |
| `tealql.tealtools.auth_domination.AuthDominationDetector` | State-mutating ops not dominated by a recognised sender check. |
| `tealql.security.NonUniqueBoxKeyDetector` | Non-unique external fields (e.g. `AssetName`) flowing into a box key. Registered as the `box-key` detection — run via `tealql detections --detector box-key`. |
| `tealql.tealtools.inner_txn_report.InnerTxnReport` | Per-`itxn_submit` group dump: each txn's fields and possible operand values. |
| `tealql.tealtools.group_reasoning.analyze` | Group shape the contract forces on every approving exit (`Global.GroupSize == 2`, `gtxn[0].Receiver == ...`, etc.). |
| `tealql.tealtools.dataflow.box` | Box dataflow in three flavours: `detect_into_box_flows` (external → box write), `detect_out_of_box_flows` (box read → sensitive sink), `detect_correlated_flows` (end-to-end chain via syntactic key matching). |
| `tealql.tealtools.xcontract.XContractGraph` | Cross-contract analysis: identifies appcall itxns with a constant `ApplicationID` resolvable in a registry, runs path predicates on each callee with seeded args, computes approving-exit summaries, feeds them back into the caller's BB. Includes `cross_auth_findings` for auth-domination across the boundary. |
| `tealql.tealtools.dataflow.predicate_aware.filter_validated` | Wraps a taint detector — suppresses violations whose sink operand is constrained by a dominating path predicate. |

The table above is a curated subset. The full detection suite is 36 registered
detectors (`tealql detections --list`), auto-discovered from
`src/tealql/security/detections/` — including the interprocedural `ir-*` family
that runs on the lifted IR.

**Decompilation & recovery** (need the `lift` extra) — reconstruct what compilation erased.

| Module | What it recovers |
| --- | --- |
| `tealql.tealtools.lift.to_puya_ir` | Scalar / ARC-4 type recovery on the lifted Puya IR: a confident tier (refines the real `ir_type`, TEAL-neutral) + a speculative side-channel (`guess_encoded_types_scored` → ARC-4 String / arrays / structs / addresses, each with a confidence flag). |
| `tealql.tealtools.lift.box_recovery.recover_storage_schema` | Puya `ContractState` schema — global / local / box single keys and maps, with recovered key/value types incl. composite tuple keys; interprocedural key resolution. |
| `tealql.tealtools.lift.box_recovery.box_access_control` | Cross-user box access: a caller-supplied address-keyed `BoxMap` not bound to `txn Sender` (the `box-audit` detection). |

### Example: run a detector

```python
from tealql.tealtools import SSAProgram, AuthDominationDetector

prog = SSAProgram("tests/tealtools/auth_domination/vuln/prog.teal")
for v in AuthDominationDetector(prog).detect():
    print(v.pretty())
```

### Example: cross-contract auth domination

```python
from tealql.tealtools import SSAProgram, XContractGraph, cross_auth_findings, load_registry

registry = load_registry("path/to/registry.yml")  # AppID → .teal path
caller = SSAProgram("path/to/caller.teal")
graph = XContractGraph.build(caller, registry)
for f in cross_auth_findings(graph):
    print(f.violation.pretty())
```

The notebooks under `playground/interactive-examples/` (`example.ipynb`, `example_xgov.ipynb`, `example_inner_txn_report.ipynb`, `example_box_key_detection.ipynb`, `example_path_predicates.ipynb`) walk through the same modules interactively.

### Puya-IR lift

`tealql.tealtools.lift` lifts the reconstructed SSA into genuine [Puya](https://github.com/algorandfoundation/puya) IR (`puya.ir.models`), validating and optimising it with Puya's own passes:

```bash
uv run python -m tealql.tealtools.lift <teal-source> [--optimize]
```

### Type recovery & decompilation (needs the `lift` extra)

On the lifted IR, the toolkit recovers types that are **not in the deployed bytecode**:

- **Scalar / ARC-4 types** — a two-tier recovery (a *confident* tier that refines the real `ir_type`, proven TEAL-neutral by `tests/test_recovery_neutral.py`, plus a *speculative* side-channel of `arc4.String` / arrays / structs / addresses with a fully-vs-somewhat confidence flag).
- **Storage schema** — reconstructs Puya's `ContractState` model (global / local / box keys and maps, with recovered key/value types incl. composite tuple keys) via `tealql storage-schema`.

Two type-driven security audits are built on it: `tealql abi-audit` (caller-supplied `arc4.Address` paid to a fund/asset sink unguarded) and `tealql box-audit` (caller-supplied address-keyed `BoxMap` not bound to `txn Sender` — cross-user box access). Both need `pip install -e '.[lift]'`.

---

## Running Tests

```bash
uv sync --extra dev        # pytest + xdist + timeout + coverage  (or: pip install -e '.[dev]')
uv run pytest tests/ -q
uv run pytest tests/ --cov # with coverage (config + regression floor in pyproject)
```

The suite is pure Python — no CodeQL, JVM, or network needed for the core tests.

### Detector precision / recall

Detector quality is a measured number, not an anecdote:
`tests/test_benchmark.py` scores every detector against a ground-truth corpus
(`tests/benchmark/<detector>/{vuln,safe}/`) and pins the confusion matrix.
The published table lives in [`docs/PRECISION.md`](docs/PRECISION.md)
(regenerate with `uv run python -m tests.gen_precision`); see
[`tests/benchmark/README.md`](tests/benchmark/README.md) to add cases. Note the
caveat there — perfect scores on a curated corpus are a *specification*, not a
field false-positive rate.

### Snapshot harness

`tests/test_python_analyses.py` runs every analysis against fixtures under `tests/tealtools/<analysis>/[<case>/]` (each holds a `.teal` source plus a committed `graph_golden.txt`) and diffs output against checked-in `expected.txt`. The dispatch routes by the top-level analysis directory name; `xcontract/` and `box_df/` use case-name prefixes for sub-flavours.

```bash
# Verify all snapshots
uv run pytest tests/test_python_analyses.py -v

# Regenerate baselines after an intended behaviour change
UPDATE_SNAPSHOTS=1 uv run pytest tests/test_python_analyses.py -v
```

### Graph golden fixtures

`tests/test_graph_golden.py` pins the pure-Python graph producers (`nodes` / `cfgEdges` / `basicBlocks`) to a committed `graph_golden.txt` per fixture. Regenerate after an intentional change to the producers:

```bash
uv run python -m tests.gen_graph_golden
```

---

## Prerequisites

- Python 3.12+ with the package installed (`uv sync`, or `pip install -e .`, pulls in the runtime deps, including the pinned tree-sitter TEAL grammar). `uv` auto-manages the interpreter.
- The test suite via `uv sync --extra dev` (or `pip install -e '.[dev]'`), run with `uv run pytest`.

---

Made with love.

If you're into this kind of stuff, check out [TEALFuzz](https://github.com/Argimirodelpozo/TEALFuzz) — a custom fuzzer for TEAL programs that uses TealQL to aid in fuzzing campaign setup.
