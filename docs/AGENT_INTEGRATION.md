# Agent integration — using TealQL from an LLM

TealQL exposes its analysis to AI agents through three layers, all in
`src/tealql/agent/`:

| Layer | What it is | Entry point |
| --- | --- | --- |
| Tool registry | 16 typed, JSON-in/JSON-out functions over the analysis | `tealql.agent.tools.TOOLS`, `call_tool(name, args)` |
| Contract brief | one structured summary of a program for triage | `tealql brief`, `tealql_brief` |
| MCP server | the registry over the Model Context Protocol (stdio) | `tealql mcp`, `.mcp.json` |

No new analysis lives here. Every tool composes existing engines (the
detectors, `TaintQuery`, `verify_sinks`, the reports, the lift's schema
recovery, the visualization catalog) and inherits their caveats, which the
payloads state explicitly.

## Contracts the agent layer keeps

1. **Completeness is data.** Any tool whose analysis can be partial returns
   `complete: bool` and `notifications: [...]` (the same envelope the CLI and
   SARIF use). "No findings" and "never analyzed" are distinguishable without
   reading logs.
2. **Over-approximation is labelled.** `tealql_taint_query` and the
   reachability fields of `tealql_source_context` are coarse reachability; the
   payload says so in `semantics`. Verdicts come only from `tealql_analyze`,
   `tealql_verify_sinks`, `tealql_brief` (which embeds both) and `tealql_diff`.
3. **Mode is replayed.** `tealql_analyze` returns, per program, the mode it
   resolved (`app` / `logicsig`, inferred from opcodes when `mode="auto"`) and
   the detectors that actually ran, so a logicsig-only detector that did not
   apply is never mistaken for a detector that ran clean.
4. **Malformed calls are the caller's error.** Arguments are validated against
   each tool's JSON Schema before anything runs; a bad call returns a tool error
   the model can read and retry, never a traceback.
5. **Stable identities.** Findings carry the versioned `Finding` schema
   (`rule_id, severity, confidence, message, file, line, witness, details`) plus
   the baseline-compatible `fingerprint`. `tealql_diff` keys on a line- and
   filename-insensitive identity so a PR that only shifts lines shows no change.

## Tools

| Tool | Answers | Verdict? |
| --- | --- | --- |
| `tealql_brief` | "What is this contract and where is it weak?" — version/mode, ABI methods with line spans, lifecycle (updatable/deletable, creator-gated, time-delayed), storage schema, inner txns, forced group shape, attack surface with verdicts, findings, health, a 3–6 line headline | yes |
| `tealql_verify_sinks` | every attacker-reachable dangerous sink labelled CONFIRMED / NOT_FLAGGED / UNVERIFIED | yes |
| `tealql_analyze` | detector findings (normalized schema) + summary + which detectors ran | yes |
| `tealql_diff` | findings added/removed between two revisions + bounded semantic equivalence | yes |
| `tealql_taint_query` | reachability: attack surface, sinks from a line, sources to a line, `--from-src` high-level line, sink/source inventories | no (over-approx.) |
| `tealql_source_context` | one line explained: window, high-level origin, ABI method, SSA instruction, dominating path predicates, reaching sources, reachable sinks | mixed, labelled |
| `tealql_decompile` | a readable view: typed pre-IR (default), Puya IR, presentation SSA, path predicates, authority, loop bounds, … | n/a |
| `tealql_methods` | ABI table with selectors, byte widths, line spans, routability | n/a |
| `tealql_storage_schema` | recovered global/local/box schema (needs the `lift` extra; degrades to `complete: false`) | n/a |
| `tealql_inner_transactions` | every inner-txn group with per-field possible values | n/a |
| `tealql_group_shape` | per-exit forced group constraints + layout | n/a |
| `tealql_list_detectors` | the catalogue with severity/confidence/mode/summary | n/a |
| `tealql_audit_app` | fetch a deployed app by ID and audit it (network) | yes |
| `tealql_triage_queue` | untriaged findings, severity/confidence first, `source_context` pre-joined | n/a (work list) |
| `tealql_record_triage` | store one reviewer verdict (the ONLY writing tool; additive) | advice only |
| `tealql_triage_report` | triage records joined to current findings; stale records; counts | advice only |

Program-taking tools accept `target` (a `.teal` file or a directory of them) or
`teal` (inline source, materialised to a content-addressed per-session temp file
so the whole pipeline sees a real path). Programs are cached per
(path, mtime, size), so a conversation that asks several questions about one
contract rebuilds it once.

## MCP

```bash
tealql mcp                 # serve over stdio (stdout = protocol only; logs to stderr)
tealql mcp --list-tools    # the catalogue; --json for the MCP descriptors
```

Claude Code reads the repository's `.mcp.json` (`uv run tealql mcp`). Any MCP
client works the same way:

```json
{"mcpServers": {"tealql": {"command": "tealql", "args": ["mcp"]}}}
```

The server is implemented directly over JSON-RPC 2.0 (no SDK dependency) and
supports protocol versions 2025-06-18, 2025-03-26 and 2024-11-05. `initialize`
returns `instructions` that teach the model the verdict-vs-reachability
distinction above. Tool results carry the payload as `structuredContent` and as
a pretty-printed text block. Tool-level problems come back as `isError: true`
results; only protocol problems (unknown method, malformed JSON) are JSON-RPC
errors.

## CLI equivalents

```bash
tealql brief app.teal [--json] [--coarse]           # the brief (exit 1 if findings, 2 if incomplete)
tealql explain app.teal --line 158 [--json]         # one line explained
tealql diff old.teal new.teal [--json]              # exit 1 only on NEW findings
tealql taint-query app.teal --precise --verify      # attack surface with verdicts
tealql detections app.teal --all --mode app --json  # raw detector output
tealql detections-scan dir/ --format sarif          # SARIF 2.1.0 for code scanning
```

## Suggested agent workflow

1. `tealql_brief` for the overview and the headline.
2. `tealql_verify_sinks` — work the CONFIRMED entries first.
3. `tealql_source_context` on each flagged line; read the dominating
   predicates to judge whether the detector missed a guard.
4. `tealql_decompile` (`repr.pre_ir`) when the TEAL is hard to follow.
5. Report in the user's terms, using `high_level_source` (the compiler's
   `// file.py:N` comments) when present, and say explicitly when
   `complete` was false.

## Triage loop (model as reviewer)

tealql never calls a model: the model is the MCP CLIENT. The server publishes a
`triage_findings(target)` prompt (`prompts/list` / `prompts/get`) that tells the
model to work the queue:

1. `tealql_triage_queue` — findings with no triage record yet, highest
   severity/confidence first, each with its v2 `fingerprint` and (for the first
   `limit`, default 10) the `tealql_source_context` payload for its line.
2. Read the context (and `tealql_decompile` when the TEAL is hard to follow);
   decide `true_positive` / `false_positive` / `needs_context`.
3. `tealql_record_triage` — validated write: the fingerprint must be a CURRENT
   finding of the target, `rationale` must be non-empty, and a
   `false_positive` must cite `evidence_lines` (the guarding TEAL lines, in
   range). Annotated `readOnlyHint: false`, `destructiveHint: false`.
4. `tealql_triage_report` — records joined to the current findings: live,
   **stale** (the fingerprint is no longer produced — the program or detector
   changed; re-triage), untriaged, counts per verdict and detector.

The store is JSON, default `<scan root>/.tealql/triage.json` (`--store` /
`store` override), keyed by `fingerprint:rule:file`; each record holds the
verdict, rationale, evidence lines, reviewer, timestamp, tool version and a
snapshot of the finding. The scan root is stored relative to the store, so a
store moved with the code keeps matching.

**Verdicts are advice.** They never change a finding's detector verdict,
severity, or exit code. The one opt-in effect is the baseline export:

```bash
tealql triage dir/ [--store PATH] [--json]          # report (exit 2 if the scan was incomplete)
tealql triage dir/ --export-baseline fp.json        # v2 baseline of ONLY false_positive-triaged findings
tealql detections-scan dir/ --baseline fp.json      # CI suppresses exactly those, with an audit trail
tealql triage-eval --store PATH [--json]            # agreement with the labelled benchmark
```

The exported baseline carries a `triage` array (who, when, why, which lines)
beside the fingerprints; it refuses to export from an incomplete scan.

**Measure before trusting.** `tealql triage-eval` compares stored verdicts
with `tests/benchmark/<detector>/{vuln,safe}/`: a record on a `vuln` fixture of
its own detector should be `true_positive`, on a `safe` fixture
`false_positive`; `needs_context` is an abstention, and another detector's
finding on a fixture is unlabelled (excluded). It prints agreement per
detector and lists each disagreement. Run the model's triage over the
benchmark fixtures (one target per fixture into one `--store`) and check this
rate per detector before letting its `false_positive` verdicts feed a
baseline — a reviewer that agrees on `rekey-to` may not on
`unvalidated-group-sibling`. Note the safe side is thin: a detector rarely
fires on its own safe fixtures, so most labelled records will be `vuln`;
agreement there measures whether the reviewer *keeps* true positives, which is
exactly the failure a false_positive-fed baseline must not have.

## Tests

`tests/test_agent_tools.py` pins the tool contracts (schemas, validation,
finding schema, mode replay, cache identity, degraded backends, the brief, the
diff) and `tests/test_mcp_server.py` the protocol surface (handshake, version
negotiation, error taxonomy, a stdio subprocess whose stdout carries only
protocol messages). `tests/test_agent_triage.py` pins the triage store
(validation, round trip, staleness, baseline export through
`detections-scan --baseline`, benchmark agreement) and `test_mcp_server.py` the
`triage_findings` prompt and the record tool's annotations.
