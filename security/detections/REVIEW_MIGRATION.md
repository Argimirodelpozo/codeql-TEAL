# Sec-Guide Detections: Test Suite Migration Summary

This document summarizes the migration from the Algorand DevRel **smart-contract-examples** artifact tree (previously vendored under `real-world-examples/`) into `security/detections/`, for mentor review.

The **real-world-examples** checkout has since been removed from this repo; sources are cited from the original paths under `smart-contract-examples/.../artifacts/`.

---

## 1. Inventory: DevRel artifact folders migrated

The following **numbered chapter folders** from the DevRel examples were used as the basis for **Gabe** (`gabe_fixed` / `gabe_vuln`) pairs:

| DevRel folder (artifacts path) | Target `security/detections/` folder(s) | Primary source TEAL (compiler output) |
|--------------------------------|------------------------------------------|----------------------------------------|
| `6-rekeying-draining/` | `rekey-to/` | `SafeLogicSig.teal` |
| `4-transaction-input-validation/` | `asset-close-to/`, `asset-id-validation/` | `SecureDepositContract.approval.teal` |
| `3-fee-management/` | `fee-validation/` | `BoundedFeeSig.teal`, `UnboundedFeeSig.teal` |
| `7-group-transaction-security/` | `group-size-check/` | `VulnerableGroupContract.approval.teal` (plus explicit `GroupSize` check on the fixed variant) |
| `10-updatability-deletability/` | `is-updatable/` | `UpgradeableContract.approval.teal` |

**Additional real-world source** (same repo, different chapter) used where chapter 10 did not provide a delete-focused approval program:

| DevRel folder | Target folder(s) | Primary source TEAL |
|---------------|------------------|---------------------|
| `2-access-control/` | `is-deletable/`, `unprotected-deletable/` | `SafeDeleteContract.approval.teal`, `VulnerableContract.approval.teal` |

---

## 2. Pairing status: `gabe_fixed.teal` and `gabe_vuln.teal`

For every migrated category below, **both** files exist. The **vuln** variant documents (in a header comment) which safeguard was removed or which weaker artifact was chosen.

| Detection folder | `gabe_fixed.teal` | `gabe_vuln.teal` — security check removed / weaker behavior |
|------------------|-------------------|---------------------------------------------------------------|
| `rekey-to/` | `SafeLogicSig` (RekeyTo == ZeroAddress among other checks) | RekeyTo-vs-zero check removed; CloseRemainderTo check retained |
| `asset-close-to/` | `SecureDepositContract` deposit path + **`gtxns AssetCloseTo == ZeroAddress`** (added for this query; not in raw DevRel output) | Same deposit logic **without** the AssetCloseTo validation |
| `asset-id-validation/` | Full `SecureDepositContract` (XferAsset vs global `"asset"`) | XferAsset / accepted-asset equality block removed on `deposit` |
| `fee-validation/` | `BoundedFeeSig` (`Txn.fee <= Global.minTxnFee`) | `UnboundedFeeSig` (no fee cap) |
| `group-size-check/` | `VulnerableGroupContract` + **`global GroupSize == 2`** at start of `buyCredit` | Original `VulnerableGroupContract` (gtxn without GroupSize) |
| `is-updatable/` | `UpgradeableContract` (admin + `upgradeReady` + timelock on update) | Update path reduced to unconditional approval (guards stripped) |
| `is-deletable/` | `SafeDeleteContract` (creator + drain precondition) | `VulnerableContract` (unrestricted delete route) |
| `unprotected-deletable/` | `SafeDeleteContract` | Same structure **without** `sender == creator` on delete; drain check retained |

**Note:** `asset-close-to` **fixed** is intentionally **derived**: DevRel `SecureDeposit` did not emit `AssetCloseTo` checks; the fixed sample adds the minimal check the CodeQL rule expects.

---

## 3. Triage report

### 3.1 Moved to `experimental-archive/`

Generic **LLM-style** `fixed.teal` / `vuln.teal` pairs were moved under `experimental-archive/<detection-folder>/` for these packs (16 files total):

- `rekey-to/`
- `asset-close-to/`
- `asset-id-validation/`
- `fee-validation/`
- `group-size-check/`
- `is-updatable/`
- `is-deletable/`
- `unprotected-deletable/`

Each archived directory contains the former `fixed.teal` and `vuln.teal` where they existed.

### 3.2 Kept in main folders (stress / edge-case TEAL)

These **non-`gabe_*`** files were **retained** in place to exercise subroutine flows, dispatch tables, partial branches, and bypass patterns (high value for query robustness):

| Folder | Stress-test style files (representative) |
|--------|------------------------------------------|
| `rekey-to/` | `fixed-callsub.teal`, `vuln-subroutine-bypass.teal`, `vuln-partial-branch.teal` |
| `asset-close-to/` | `fixed-multi-branch.teal`, `vuln-multi-branch.teal` |
| `fee-validation/` | `fixed-callsub.teal`, `vuln-branch-skip.teal`, `vuln-subroutine-dead.teal` |
| `group-size-check/` | `fixed-gtxn-in-subroutine.teal`, `vuln-gtxn-in-subroutine.teal`, `vuln-conditional-gtxn.teal` |
| `is-updatable/` | `vuln-fallthrough.teal` |
| `is-deletable/` | `fixed-complex-dispatch.teal`, `vuln-complex-dispatch.teal` |
| `unprotected-deletable/` | `fixed-dispatch-table.teal`, `vuln-dispatch-table.teal` |
| `unprotected-updatable/` | `fixed-dispatch-table.teal`, `vuln-dispatch-table.teal`, `vuln-nested-dispatch.teal` |
| `close-remainder-to/` | `fixed-callsub.teal`, `vuln-split-paths.teal`, `vuln-loop-like.teal` |
| `tx-type-check/` | `fixed-subroutine-dispatch.teal`, `vuln-subroutine-dispatch.teal` |
| `timelock-upgrade/` | `fixed-complex-dispatch.teal`, `vuln-complex-dispatch.teal` |
| `unsafe-lsig-args/` | `vuln-callsub.teal`, `vuln-nested-sub.teal`, `vuln-branch-merge.teal` |
| `inner-txn-fee/` | `vuln-dynamic-fee.teal` |
| `inner-txn-close-rekey/` | `vuln-conditional-itxn.teal` |

Other folders (`delete-funds-check`, `hardcoded-min-balance`, etc.) still use their original `fixed.teal` / `vuln.teal` pattern and were not part of the Gabe archive sweep.

---

## 4. Infrastructure

### `run_tests.sh`

- **Location:** `security/detections/run_tests.sh`
- **Purpose:** Run `codeql test run` over this pack with:
  - `ROOT` = repository root (two levels up from this script)
  - `CODEQL_EXTRACTOR_TEAL_ROOT` → `$ROOT/.codeql-extractors/teal`
  - `--search-path=$ROOT/.codeql-extractors` (avoids duplicate TEAL extractor roots under `teal/` and `teal/extractor-pack/`)
  - `--additional-packs=$ROOT/teal/ql/lib` for `argimirodelpozo/teal-all`
  - `--learn` for updating baselines when outputs change intentionally

### `.expected` files

There are **17** query directories with **`*.expected`** files (one per main `.ql` query). These record the **qltest baseline** so CI / local runs catch regressions in extraction, compilation, or query results.

---

## 5. Gaps: DevRel folders not migrated (no matching sec-guide query yet)

The following **artifact areas** existed in the DevRel tree but were **not** pulled into `security/detections/` as Gabe pairs, mainly because there is **no corresponding** `security/detections/<rule>/` query (or overlap was deemed out of scope):

| DevRel area (examples) | Why not migrated here |
|-------------------------|-------------------------|
| `1-smart-contracts-vs-logic-signatures/` (e.g. escrow / payment manager / LSIG patterns) | No dedicated sec-guide pack folder for “contract vs LSIG” parity; some themes overlap `unsafe-lsig-args` but examples differ |
| `2-access-control/` — **remainder** (e.g. `RoleBasedContract`, `SafeDefaultContract`, `SecureContract` update paths) | Only delete-focused contracts were used for `is-deletable` / `unprotected-deletable` |
| `8-state-management/` (loan, min-balance, pull pattern) | Partial conceptual overlap with `hardcoded-min-balance`; no one-to-one migration performed from these artifacts |
| `9-arithmetic-safety/` / `arithmetic_safety/` | No arithmetic-safety sec-guide query in this pack |
| `14-off-chain-operational-security/` (e.g. pausable contract) | No pausable / ops-sec sec-guide query in this pack |
| `hello_world/` | Tutorial-only; no security query target |
| `fee_verification_test/` / other small demos | Narrow or redundant vs `fee-validation` |

**Follow-up (optional):** Add new `security/detections/<topic>/` queries (and qltests) for arithmetic safety, access-control breadth, or operational pause patterns, then attach DevRel TEAL as `gabe_*` pairs.

---

## 6. Quick verification

From repository root:

```bash
./security/detections/run_tests.sh
```

All **17** qltests should **extract, compile, and match** their `.expected` baselines when the toolchain and pack layout are unchanged.
