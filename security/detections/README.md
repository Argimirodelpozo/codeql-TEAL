# Algorand Security-Guide Detections

Each subdirectory here is one self-contained Algorand-security-guide detection:
a CodeQL query (`.ql`) and its checked-in baseline (`.expected`), a Python port
(`.py`) over the `tealtools` SSA substrate, fixture programs (`*.teal`), and a
`README.md` explaining what the detection looks for and how it works.

Both implementations preserve the same QL semantics — the Python ports were
deliberately ported from the QL form, including the over-conservative shapes
(e.g. `match`/`switch` dispatch tables aren't recognised as OnCompletion
guards). Tighter detectors are deliberate follow-ups, not changes to these
ports.

## Detections

| Detection | Severity | Shape | What it catches |
| --- | --- | --- | --- |
| [`asset-close-to`](asset-close-to/) | high | strict-dominance txn-field | `AssetCloseTo` never validated → asset balance can be drained |
| [`asset-id-validation`](asset-id-validation/) | high | anywhere-checked | handles axfer without checking `XferAsset` |
| [`close-remainder-to`](close-remainder-to/) | high | strict-dominance txn-field | `CloseRemainderTo` never validated → ALGO balance can be drained |
| [`delete-funds-check`](delete-funds-check/) | high | OnCompletion + global | DeleteApplication reachable without `balance` / `min_balance` opcode pair |
| [`fee-validation`](fee-validation/) | high | anywhere-checked | `Fee` never bounded → LogicSig can be drained via fee inflation |
| [`group-size-check`](group-size-check/) | high | per-opcode + global | absolute `gtxn N` without a `GroupSize` check |
| [`hardcoded-min-balance`](hardcoded-min-balance/) | medium | opcode pattern | subtracting a literal from `balance` (instead of using `min_balance`) |
| [`inner-txn-close-rekey`](inner-txn-close-rekey/) | high | per-itxn-field | inner tx sets `CloseRemainderTo` / `RekeyTo` / `AssetCloseTo` |
| [`inner-txn-fee`](inner-txn-fee/) | high | per-itxn-field | inner tx sets non-zero constant `Fee` |
| [`is-deletable`](is-deletable/) | high | OnCompletion-guard | DeleteApplication reachable on any approval exit |
| [`is-updatable`](is-updatable/) | high | OnCompletion-guard | UpdateApplication reachable on any approval exit |
| [`rekey-to`](rekey-to/) | high | per-exit path-aware | unprotected approval exit allows `RekeyTo` |
| [`timelock-upgrade`](timelock-upgrade/) | medium | OnCompletion-guard + global | UpdateApplication with creator guard but no timestamp check |
| [`tx-type-check`](tx-type-check/) | high | strict-dominance txn-field | neither `TypeEnum` nor `Type` validated |
| [`unprotected-deletable`](unprotected-deletable/) | high | OnCompletion + auth | DeleteApplication reachable without sender == creator guard |
| [`unprotected-updatable`](unprotected-updatable/) | high | OnCompletion + auth | UpdateApplication reachable without sender == creator guard |
| [`unsafe-lsig-args`](unsafe-lsig-args/) | high | dataflow | LogicSig uses `arg N` in an auth-style comparison |

## Detection shapes — vocabulary

- **strict-dominance txn-field** — a single comparison against `<FIELD>` must dominate every approval exit. One finding per program. Implementation: `txnFieldValidatedOnAllPaths(field)` (QL) / `_FieldValidatedDetector` (Python).
- **anywhere-checked** — the check just has to exist *somewhere* in the program. One finding per program.
- **per-exit path-aware** — examine each approval exit's dominating predicates individually. One finding per unprotected exit. Implementation: `approvalExitProtectedForField` (QL) / `PathPredicateAnalysis` (Python).
- **OnCompletion-guard** — flag each approval exit reachable under a dangerous `OnCompletion` value. Optional conjuncts: `senderCreatorGuardDominates` for the *unprotected* variants, presence of specific opcodes (`balance`/`min_balance`, `Global.LatestTimestamp`) for funds-safety variants.
- **per-itxn-field** / **per-opcode** / **opcode pattern** — simple syntactic walks over the IR with optional global-presence exemptions.
- **dataflow** — trace SSAVar uses from a source opcode to a sink predicate.

## Shared infrastructure

- `SecGuideCommon.qll` — every CodeQL detection's helper library: `approvalExit()`, `approvalExitProtectedForField`, `txnFieldValidatedOnAllPaths`, `senderCreatorGuardDominates`, etc.
- `qlpack.yml` — declares this directory as the `argimirodelpozo/teal-detections` CodeQL pack.
- `run_tests.sh` — `codeql test run security/detections/` driver.
- `build_test_databases.sh` — bulk-rebuilds the per-detection fixture DBs under `security/detections-dbs/`.

Python-side shared helpers live in `analysis/tealtools/detections/`:
`common.py` (approval exits, OnCompletion guards, field-validated checks),
`_field_validated.py` (base class for strict-dominance txn-field detectors),
`xcontract.py` (cross-contract findings driver), `scan.py` (directory-walking
scanner that builds per-dir DBs and runs detections).

## Running

```bash
# List every detection short name
python -m tealtools detections --list

# Run one detection (or --all)
python -m tealtools detections --detector rekey-to <path/to/db-or-source>

# Run every native CodeQL test in this directory
./security/detections/run_tests.sh
```

Non-detection sibling directories (`constant-propagation-tests/`,
`phi-liveness/`, `puya-benchmarks/`, `experimental-archive/`) hold standalone
analysis-substrate qltests and benchmarks; they're CodeQL test infrastructure,
not security-guide detections.
