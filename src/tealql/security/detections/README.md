# Algorand Security-Guide Detections

Each subdirectory here is one Algorand-security-guide detection: a Python
detector (`.py`) and a `README.md` explaining what the detection looks
for and how it works. Test fixtures (`.teal` programs, built DBs,
expected output) live separately, under `tests/tealtools/sec_guide/`.

Each policy lives at the representation that preserves the facts it needs:
immutable SSA facts for constants and ranges, CFG/path predicates for approval
and lifecycle guards, typed pre-IR for interprocedural attacker flows, and the
SuperCFG for cross-contract reasoning. Policy names describe the vulnerability,
not their implementation layer.

## Detections

| Detection | Severity | Shape | What it catches |
| --- | --- | --- | --- |
| [`abi-method-selector`](abi-method-selector/) | medium | SSA + path predicates | argument use without enforced ABI method dispatch |
| [`arbitrary-inner-appcall`](arbitrary-inner-appcall/) | high | lifted taint | attacker-controlled inner application target |
| [`arbitrary-inner-asset`](arbitrary-inner-asset/) | high | lifted taint | attacker-controlled inner asset selector |
| [`tainted-asset-admin`](tainted-asset-admin/) | medium–critical | lifted taint | attacker-controlled asset manager/reserve/freeze/clawback |
| [`tainted-state-write`](tainted-state-write/) | medium–critical | lifted taint | attacker-controlled state or box key |
| [`tainted-log`](tainted-log/) | low | lifted taint | attacker-controlled log payload |
| [`tainted-freeze`](tainted-freeze/) | medium–high | lifted taint | attacker-controlled freeze target/account |
| [`tainted-fee`](tainted-fee/) | medium | lifted taint | attacker-controlled inner transaction fee |
| [`asset-close-to`](asset-close-to/) | high | strict-dominance txn-field | `AssetCloseTo` never validated → asset balance can be drained |
| [`asset-id-validation`](asset-id-validation/) | high | anywhere-checked | handles axfer without checking `XferAsset` |
| [`box-key`](box-key/) | high | dataflow | non-unique field (`AssetName`) flows into a box key → collisions |
| [`close-remainder-to`](close-remainder-to/) | high | strict-dominance txn-field | `CloseRemainderTo` never validated → ALGO balance can be drained |
| [`constant-condition`](constant-condition/) | medium | immutable ranges | provably constant branch/assert condition |
| [`delete-funds-check`](delete-funds-check/) | high | OnCompletion + global | DeleteApplication reachable without `balance` / `min_balance` opcode pair |
| [`fee-validation`](fee-validation/) | high | anywhere-checked | `Fee` never bounded → LogicSig can be drained via fee inflation |
| [`group-size-check`](group-size-check/) | high | per-opcode + global | absolute `gtxn N` without a `GroupSize` check |
| [`hardcoded-min-balance`](hardcoded-min-balance/) | medium | opcode pattern | subtracting a literal from `balance` (instead of using `min_balance`) |
| [`inner-txn-close-rekey`](inner-txn-close-rekey/) | high | per-itxn-field | inner tx sets `CloseRemainderTo` / `RekeyTo` / `AssetCloseTo` |
| [`inner-txn-fee`](inner-txn-fee/) | high | per-itxn-field | inner tx sets non-zero constant `Fee` |
| [`is-deletable`](is-deletable/) | informational | OnCompletion-guard | DeleteApplication reachable on any approval exit |
| [`is-updatable`](is-updatable/) | informational | OnCompletion-guard | UpdateApplication reachable on any approval exit |
| [`lease-validation`](lease-validation/) | medium | txn-field enforcement | `Lease` never validated by a LogicSig |
| [`rekey-to`](rekey-to/) | high | per-exit path-aware | unprotected approval exit allows `RekeyTo` |
| [`timelock-upgrade`](timelock-upgrade/) | medium | OnCompletion-guard + global | UpdateApplication with creator guard but no timestamp check |
| [`tainted-fund-flow`](tainted-fund-flow/) | medium–critical | lifted taint | attacker-controlled inner payment/asset fund field |
| [`partial-tainted-fund-flow`](partial-tainted-fund-flow/) | medium–high | lifted byte taint | unchecked attacker-controlled slice reaches a fund field |
| [`tx-type-check`](tx-type-check/) | high | strict-dominance txn-field | neither `TypeEnum` nor `Type` validated |
| [`unprotected-deletable`](unprotected-deletable/) | high | OnCompletion + auth | DeleteApplication reachable without sender == creator guard |
| [`unprotected-updatable`](unprotected-updatable/) | high | OnCompletion + auth | UpdateApplication reachable without sender == creator guard |
| [`unvalidated-group-sibling`](unvalidated-group-sibling/) | high | SSA + group paths | sibling transfer trusted without enforced receiver pin |
| [`unsafe-division-order`](unsafe-division-order/) | medium | immutable facts + flow | precision-losing divide-before-multiply arithmetic |
| [`unsafe-lsig-args`](unsafe-lsig-args/) | high | dataflow | LogicSig uses `arg N` in an auth-style comparison |

## Detection shapes — vocabulary

- **strict-dominance txn-field** — a single comparison against `<FIELD>` must dominate every approval exit. One finding per program. Implemented by `_FieldValidatedDetector`.
- **anywhere-checked** — the check just has to exist *somewhere* in the program. One finding per program.
- **per-exit path-aware** — examine each approval exit's dominating predicates individually. One finding per unprotected exit. Built on `PathPredicateAnalysis`.
- **OnCompletion-guard** — flag each approval exit reachable under a dangerous `OnCompletion` value. Optional conjuncts: `senderCreatorGuardDominates` for the *unprotected* variants, presence of specific opcodes (`balance`/`min_balance`, `Global.LatestTimestamp`) for funds-safety variants.
- **per-itxn-field** / **per-opcode** / **opcode pattern** — simple SSA walks with immutable constant facts and optional global-presence exemptions.
- **dataflow** — trace SSAVar uses from a source opcode to a sink predicate.

## Shared infrastructure

Python-side shared helpers live in `tealql/security/` and import their owning
analysis modules directly:

- `_program_shape.py`, `_field_protection.py`, and `_action_guards.py` own SSA,
  approval-path, and lifecycle reasoning respectively.
- `_lifted_taint_sink.py` is the common lifted-policy base; lift failure is an
  explicit incomplete-analysis notification, never a semantic fallback.
- `xcontract.py` is the cross-contract findings driver (walks appcall itxns,
  resolves the callee in a registry, propagates seeded path predicates).
- `scan.py` walks source files independently and accepts one `DetectionOptions`
  schema for selection, mode, severity, and failure thresholds.

This directory holds only the Python detectors.

## Running

```bash
# List every detection short name
python -m tealql.tealtools detections --list

# Run one detection (or --all)
python -m tealql.tealtools detections --detector rekey-to <path/to/db-or-source>
```
