# Detector precision / recall

36 detectors · 74 vulnerable + 84 safe ground-truth cases.

> **Read this first.** These numbers are measured on a **small, curated**
> ground-truth corpus (`tests/benchmark/<detector>/{vuln,safe}/`), not on a
> random sample of real-world contracts. A perfect score means the detector
> behaves as intended on the cases we wrote to characterise it — it is a
> **regression gate and a specification**, not a field false-positive rate.
> Where a detector has a known blind spot, the corpus encodes it as a real
> FN/FP so the limitation is a number, not a footnote. Grow the corpus (see
> `tests/benchmark/README.md`) to make the numbers more representative.

| Detector | Severity | Confidence | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --: | --: | --: | --: | --: | --: | --: |
| `abi-method-selector` | medium | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `arbitrary-inner-appcall` | medium | high | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 1.00 |
| `arbitrary-inner-asset` | medium | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `asset-close-to` | high | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `asset-id-validation` | high | high | 1 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `box-key` | high | high | 3 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `close-remainder-to` | high | high | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `constant-condition` | medium | high | 3 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `delete-funds-check` | high | high | 2 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `fee-validation` | high | high | 1 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `group-size-check` | high | high | 1 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `hardcoded-min-balance` | medium | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `inner-txn-close-rekey` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `inner-txn-fee` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `ir-arbitrary-inner-appcall` | medium | high | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 1.00 |
| `ir-arbitrary-inner-asset` | medium | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `ir-partial-tainted-fund-flow` | medium | high | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-asset-admin` | medium | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-fee` | medium | high | 1 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-freeze` | medium | high | 1 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-fund-flow` | medium | high | 5 | 0 | 0 | 6 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-log` | medium | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `ir-tainted-state-write` | medium | high | 2 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `is-deletable` | informational | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `is-updatable` | informational | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `lease-validation` | medium | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `partial-tainted-fund-flow` | medium | high | 3 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `rekey-to` | high | high | 4 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `tainted-fund-flow` | medium | high | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 1.00 |
| `timelock-upgrade` | medium | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `tx-type-check` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `unprotected-deletable` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `unprotected-updatable` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `unsafe-division-order` | medium | high | 3 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 |
| `unsafe-lsig-args` | high | high | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| `unvalidated-group-sibling` | medium | high | 4 | 0 | 0 | 5 | 1.00 | 1.00 | 1.00 |
| **overall** | | | **74** | **0** | **0** | **84** | **1.00** | **1.00** | **1.00** |

_Regenerate with_ `python -m tests.gen_precision`.
