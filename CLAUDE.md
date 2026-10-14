# TealQL — guidance for coding agents

TealQL is a pure-Python static analyzer and decompiler for Algorand TEAL
(`src/tealql/`). It parses `.teal` with a pinned tree-sitter grammar, rebuilds
typed SSA, lifts it to a Puya-shaped IR, and runs 32 security detectors plus
reports on top. No CodeQL, no network, no build step for the core path.

## Layout

- `src/tealql/tealtools/` — analysis substrate: `ast/` `cfg/` `ssa/` (SSA via
  the shared stack simulator `ssa/stacksim.py`), `analysis/` (immutable facts:
  constants, aliases, ranges, byte lengths), `dataflow/` (taint, byte taint,
  taint query), `lift/` (pre-IR, guards, fund flow, Puya lowering), `budget/`,
  `intercontract/`, `reporting/`, `diagnostics/`, `viz/`.
- `src/tealql/security/` — detectors (`detections/<kebab>/<snake>.py`, one dir
  each, auto-discovered via `_DETECTION_ORDER`), scanner, SARIF/JSON renderers,
  suppressions, sink verdicts. Depends on `tealtools`, never the reverse.
- `src/tealql/agent/` — agent-facing surface: tool registry (`tools.py`),
  contract brief (`brief.py`), dependency-free MCP server (`server.py`).
- `src/tealql/cli/` — the `tealql` console entry point.
- `tests/` — hermetic suite. `tests/benchmark/<detector>/{vuln,safe}/` is the
  detector ground truth; `tests/mainnet-random-probes/` + `tests/mainnet_ratchet.py`
  pin findings on ~1000 real programs; `tests/contracts/` are real apps.

## Commands

```bash
uv sync --extra lift --extra dev              # or: pip install -e '.[lift,dev]'
uvx ruff check src/ tests/ tools/             # CI gate #1 (F + E9 only) — run before every push
uv run pytest tests/ -q -n auto               # hermetic suite (~5 min on 8 workers)
LIFT_SEMANTICS_CORPUS=1 LIFT_SEMANTICS_BACKEND=1 uv run pytest tests/ -q -n auto   # what CI runs
UPDATE_SNAPSHOTS=1 uv run pytest tests/test_python_analyses.py                    # regenerate goldens
UPDATE_MAINNET_DIGEST=1 uv run pytest tests/test_mainnet_ratchet.py               # regenerate ratchet (classify every delta first)
```

## Rules that have bitten before

- **Analyses never mutate the SSA.** New analyses are their own module plus a
  thin lazy bridge; only annotations/facts cross the lift boundary. `prog.facts(...)`
  is the read API; `derived_program` gives read-only normal forms.
- **Operand order:** `Assignment.inputs` is TOP-FIRST, `operands` is source
  order; use `binary_operands` to cross them. Never positional-read `inputs`
  of a >2-input op after a None-drop.
- **Guards:** a guard on one branch is not a guard at the join (join = OR, not
  AND); the approving `return`'s own operand IS a guard; dominance is per EDGE.
  Run `tests/test_mutation_gates.py` and the mainnet ratchet after any guard change
  and classify every changed row as TP or FP before regenerating the digest.
- **Never DSE scratch stores** (gload-readable across the group). **retsub is
  never an exit.** **Rekey is a logicsig concern** (RekeyTo is not a fund field).
- **Completeness is data:** a detector that could not run must leave a
  notification; "no findings" must never print alone when degraded. Exit codes:
  0 clean / 1 findings / 2 error-or-incomplete.
- Tests: one test per DEFECT (fold controls in), mutation-test new instruments.
  A golden regen must be proven to be pure substitution.
- Don't guess ABI signatures from selectors (hash is irreversible); they come
  from `method "sig"` pseudo-ops / `// method` comments / ARC-56.

## Using tealql from an agent

- Claude Code picks up `.mcp.json` (`uv run tealql mcp`) and gets the tools
  `tealql_brief`, `tealql_verify_sinks`, `tealql_analyze`, `tealql_taint_query`,
  `tealql_source_context`, `tealql_decompile`, `tealql_methods`,
  `tealql_storage_schema`, `tealql_inner_transactions`, `tealql_group_shape`,
  `tealql_diff`, `tealql_list_detectors`, `tealql_audit_app`, and the triage loop
  `tealql_triage_queue` / `tealql_record_triage` (the only writer; verdicts are advice) /
  `tealql_triage_report`, plus the `triage_findings` MCP prompt. `tealql mcp --list-tools` prints them.
  Measure a reviewer with `tealql triage-eval --store PATH` before trusting its verdicts.
- CLI equivalents: `tealql brief app.teal`, `tealql explain app.teal --line N`, `tealql diff old.teal new.teal`,
  `tealql taint-query app.teal --precise --verify`, `tealql detections app.teal --all --mode app --json`,
  `tealql detections-scan dir/ --format sarif`.
- Verdicts come from `analyze` / `verify_sinks` / the detectors. `taint_query`
  is over-approximate reachability. `complete: false` means part of the
  analysis did not run; absence of findings there is not evidence of safety.
