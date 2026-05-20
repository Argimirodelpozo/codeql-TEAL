# Algorand Security-Guide Detections

Each subdirectory here is one self-contained Algorand-security-guide detection:
a Python detector (`.py`) over the `tealtools` SSA substrate, fixture programs
(`*.teal`), and a `README.md` explaining what the detection looks for and how
it works.

Detectors were originally ported from CodeQL queries; the `.ql` versions have
since been retired in favour of the Python implementations, which run faster
and integrate directly with the `tealtools` pipeline (constant propagation,
range propagation, path predicates, …). The over-conservative QL shapes are
preserved (e.g. `match`/`switch` dispatch tables aren't recognised as
OnCompletion guards) — tighter detectors are deliberate follow-ups, not silent
changes.

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

- **strict-dominance txn-field** — a single comparison against `<FIELD>` must dominate every approval exit. One finding per program. Implemented by `_FieldValidatedDetector`.
- **anywhere-checked** — the check just has to exist *somewhere* in the program. One finding per program.
- **per-exit path-aware** — examine each approval exit's dominating predicates individually. One finding per unprotected exit. Built on `PathPredicateAnalysis`.
- **OnCompletion-guard** — flag each approval exit reachable under a dangerous `OnCompletion` value. Optional conjuncts: `senderCreatorGuardDominates` for the *unprotected* variants, presence of specific opcodes (`balance`/`min_balance`, `Global.LatestTimestamp`) for funds-safety variants.
- **per-itxn-field** / **per-opcode** / **opcode pattern** — simple syntactic walks over the IR with optional global-presence exemptions.
- **dataflow** — trace SSAVar uses from a source opcode to a sink predicate.

## Shared infrastructure

Python-side shared helpers live in `analysis/tealtools/detections/`:

- `common.py` — approval exits, OnCompletion guards, sender == creator,
  field-validated-on-all-paths, path-aware field-protected, inner-tx iteration.
- `_field_validated.py` — base class for strict-dominance txn-field detectors.
- `xcontract.py` — cross-contract findings driver (walks appcall itxns,
  resolves the callee in a registry, propagates seeded path predicates).
- `scan.py` — directory walker that builds per-dir DBs and runs detections.

CodeQL-side, `qlpack.yml` + `run_tests.sh` are kept here because the
test_codeql_backend.py runner still walks `security/detections/` for
`.ql` / `.qlref` files. After the recent cleanup all QL-substrate test
sets (`tests/codeql/phi-liveness/`, `tests/codeql/puya-benchmarks/`,
`tests/codeql/const_propagation/`) live under `tests/codeql/`, so the
pack here is structurally a thin shell.

## Running

```bash
# List every detection short name
python -m tealtools detections --list

# Run one detection (or --all)
python -m tealtools detections --detector rekey-to <path/to/db-or-source>

# Run every native CodeQL test in this directory
./security/detections/run_tests.sh
```

After the cleanup, only the 17 detection directories live here alongside
`qlpack.yml` / `run_tests.sh` / `REVIEW_MIGRATION.md`. Every non-detection
artifact (qltests, benchmarks, archived TEAL fixtures) moved into
`tests/codeql/` or was deleted.
