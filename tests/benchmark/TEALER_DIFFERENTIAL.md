# Tealer differential (one-time demo)

Our sec-guide detectors vs [crytic/tealer], compared per shared vulnerability class. Scoped apples-to-apples (both auto-scope app/logicsig). A tool crashing on a contract is a robustness failure for that tool. Regenerate: `TEALER=/path/to/tealer python tests/benchmark/tealer_differential.py`.

## Benchmark corpus — vuln (ground truth = vuln)

**Robustness** — we analysed **13/13**, Tealer analysed **13/13** (Tealer crashed on **0** → 0 robustness win(s) for us; we crashed on 0).

| class | agree | we-only | tealer-only |
|---|---:|---:|---:|
| deletable | 2 | 0 | 11 |
| updatable | 2 | 0 | 11 |
| rekey | 13 | 0 | 0 |
| close-account | 9 | 4 | 0 |
| close-asset | 8 | 5 | 0 |
| fee | 13 | 0 | 0 |
| group-size | 0 | 13 | 0 |

<details><summary>44 class disagreements</summary>

| label | contract | class | who flags |
|---|---|---|---|
| vuln | dropped_result_unenforced.teal | deletable | tealer-flag/we-clean |
| vuln | dropped_result_unenforced.teal | updatable | tealer-flag/we-clean |
| vuln | dropped_result_unenforced.teal | group-size | we-flag/tealer-clean |
| vuln | no_check_at_all.teal | deletable | tealer-flag/we-clean |
| vuln | no_check_at_all.teal | updatable | tealer-flag/we-clean |
| vuln | no_check_at_all.teal | group-size | we-flag/tealer-clean |
| vuln | dropped_close_check.teal | deletable | tealer-flag/we-clean |
| vuln | dropped_close_check.teal | updatable | tealer-flag/we-clean |
| vuln | dropped_close_check.teal | group-size | we-flag/tealer-clean |
| vuln | no_close_check.teal | deletable | tealer-flag/we-clean |
| vuln | no_close_check.teal | updatable | tealer-flag/we-clean |
| vuln | no_close_check.teal | group-size | we-flag/tealer-clean |
| vuln | no_check.teal | deletable | tealer-flag/we-clean |
| vuln | no_check.teal | updatable | tealer-flag/we-clean |
| vuln | no_check.teal | group-size | we-flag/tealer-clean |
| vuln | no_groupsize_check.teal | deletable | tealer-flag/we-clean |
| vuln | no_groupsize_check.teal | updatable | tealer-flag/we-clean |
| vuln | no_groupsize_check.teal | group-size | we-flag/tealer-clean |
| vuln | delete_approved_unguarded.teal | deletable | tealer-flag/we-clean |
| vuln | delete_approved_unguarded.teal | updatable | tealer-flag/we-clean |
| vuln | delete_approved_unguarded.teal | close-account | we-flag/tealer-clean |
| vuln | delete_approved_unguarded.teal | close-asset | we-flag/tealer-clean |
| vuln | delete_approved_unguarded.teal | group-size | we-flag/tealer-clean |
| vuln | update_approved_unguarded.teal | deletable | tealer-flag/we-clean |
| vuln | update_approved_unguarded.teal | updatable | tealer-flag/we-clean |
| vuln | update_approved_unguarded.teal | close-account | we-flag/tealer-clean |
| vuln | update_approved_unguarded.teal | close-asset | we-flag/tealer-clean |
| vuln | update_approved_unguarded.teal | group-size | we-flag/tealer-clean |
| vuln | approves_unchecked.teal | group-size | we-flag/tealer-clean |
| vuln | delegated_lsig_no_rekey_guard.teal | close-asset | we-flag/tealer-clean |
| vuln | delegated_lsig_no_rekey_guard.teal | group-size | we-flag/tealer-clean |
| vuln | no_check.teal | deletable | tealer-flag/we-clean |
| vuln | no_check.teal | updatable | tealer-flag/we-clean |
| vuln | no_check.teal | group-size | we-flag/tealer-clean |
| vuln | delete_no_creator_guard.teal | deletable | tealer-flag/we-clean |
| vuln | delete_no_creator_guard.teal | updatable | tealer-flag/we-clean |
| vuln | delete_no_creator_guard.teal | close-account | we-flag/tealer-clean |
| vuln | delete_no_creator_guard.teal | close-asset | we-flag/tealer-clean |
| vuln | delete_no_creator_guard.teal | group-size | we-flag/tealer-clean |
| vuln | update_no_creator_guard.teal | deletable | tealer-flag/we-clean |
| vuln | update_no_creator_guard.teal | updatable | tealer-flag/we-clean |
| vuln | update_no_creator_guard.teal | close-account | we-flag/tealer-clean |
| vuln | update_no_creator_guard.teal | close-asset | we-flag/tealer-clean |
| vuln | update_no_creator_guard.teal | group-size | we-flag/tealer-clean |

</details>

## Benchmark corpus — safe (ground truth = safe)

**Robustness** — we analysed **12/12**, Tealer analysed **12/12** (Tealer crashed on **0** → 0 robustness win(s) for us; we crashed on 0).

| class | agree | we-only | tealer-only |
|---|---:|---:|---:|
| deletable | 2 | 0 | 10 |
| updatable | 2 | 0 | 10 |
| rekey | 12 | 0 | 0 |
| close-account | 10 | 2 | 0 |
| close-asset | 8 | 3 | 1 |
| fee | 12 | 0 | 0 |
| group-size | 2 | 10 | 0 |

<details><summary>36 class disagreements</summary>

| label | contract | class | who flags |
|---|---|---|---|
| safe | asserted.teal | deletable | tealer-flag/we-clean |
| safe | asserted.teal | updatable | tealer-flag/we-clean |
| safe | asserted.teal | group-size | we-flag/tealer-clean |
| safe | bz_to_err.teal | deletable | tealer-flag/we-clean |
| safe | bz_to_err.teal | updatable | tealer-flag/we-clean |
| safe | bz_to_err.teal | group-size | we-flag/tealer-clean |
| safe | sibling_gtxn_pinned.teal | deletable | tealer-flag/we-clean |
| safe | sibling_gtxn_pinned.teal | updatable | tealer-flag/we-clean |
| safe | sibling_gtxn_pinned.teal | close-asset | tealer-flag/we-clean |
| safe | close_asserted.teal | deletable | tealer-flag/we-clean |
| safe | close_asserted.teal | updatable | tealer-flag/we-clean |
| safe | close_asserted.teal | group-size | we-flag/tealer-clean |
| safe | fee_zero_assert.teal | deletable | tealer-flag/we-clean |
| safe | fee_zero_assert.teal | updatable | tealer-flag/we-clean |
| safe | fee_zero_assert.teal | group-size | we-flag/tealer-clean |
| safe | groupsize_checked.teal | deletable | tealer-flag/we-clean |
| safe | groupsize_checked.teal | updatable | tealer-flag/we-clean |
| safe | delete_rejected.teal | updatable | tealer-flag/we-clean |
| safe | delete_rejected.teal | close-account | we-flag/tealer-clean |
| safe | delete_rejected.teal | close-asset | we-flag/tealer-clean |
| safe | delete_rejected.teal | group-size | we-flag/tealer-clean |
| safe | update_rejected.teal | deletable | tealer-flag/we-clean |
| safe | update_rejected.teal | close-account | we-flag/tealer-clean |
| safe | update_rejected.teal | close-asset | we-flag/tealer-clean |
| safe | update_rejected.teal | group-size | we-flag/tealer-clean |
| safe | delegated_lsig_rekey_guarded.teal | close-asset | we-flag/tealer-clean |
| safe | delegated_lsig_rekey_guarded.teal | group-size | we-flag/tealer-clean |
| safe | zeroaddr_assert.teal | deletable | tealer-flag/we-clean |
| safe | zeroaddr_assert.teal | updatable | tealer-flag/we-clean |
| safe | zeroaddr_assert.teal | group-size | we-flag/tealer-clean |
| safe | delete_creator_guarded.teal | deletable | tealer-flag/we-clean |
| safe | delete_creator_guarded.teal | updatable | tealer-flag/we-clean |
| safe | delete_creator_guarded.teal | group-size | we-flag/tealer-clean |
| safe | update_creator_guarded.teal | deletable | tealer-flag/we-clean |
| safe | update_creator_guarded.teal | updatable | tealer-flag/we-clean |
| safe | update_creator_guarded.teal | group-size | we-flag/tealer-clean |

</details>

## Real mainnet probes (no ground truth)

**Robustness** — we analysed **229/229**, Tealer analysed **169/229** (Tealer crashed on **60** → 60 robustness win(s) for us; we crashed on 0).

| class | agree | we-only | tealer-only |
|---|---:|---:|---:|
| deletable | 149 | 20 | 0 |
| updatable | 84 | 85 | 0 |
| rekey | 162 | 7 | 0 |
| close-account | 5 | 164 | 0 |
| close-asset | 2 | 167 | 0 |
| fee | 162 | 7 | 0 |
| group-size | 67 | 102 | 0 |

<details><summary>552 class disagreements</summary>

| label | contract | class | who flags |
|---|---|---|---|
|  | app_1050021565.teal | close-account | we-flag/tealer-clean |
|  | app_1050021565.teal | close-asset | we-flag/tealer-clean |
|  | app_1050021565.teal | group-size | we-flag/tealer-clean |
|  | app_1050030771.teal | updatable | we-flag/tealer-clean |
|  | app_1050030771.teal | close-asset | we-flag/tealer-clean |
|  | app_1050030771.teal | group-size | we-flag/tealer-clean |
|  | app_1050051256.teal | updatable | we-flag/tealer-clean |
|  | app_1050051256.teal | close-account | we-flag/tealer-clean |
|  | app_1050051256.teal | close-asset | we-flag/tealer-clean |
|  | app_1050051256.teal | group-size | we-flag/tealer-clean |
|  | app_127984669.teal | updatable | we-flag/tealer-clean |
|  | app_127984669.teal | close-account | we-flag/tealer-clean |
|  | app_127984669.teal | close-asset | we-flag/tealer-clean |
|  | app_127984669.teal | group-size | we-flag/tealer-clean |
|  | app_1300010796.teal | close-account | we-flag/tealer-clean |
|  | app_1300010796.teal | close-asset | we-flag/tealer-clean |
|  | app_1300010796.teal | group-size | we-flag/tealer-clean |
|  | app_1300027927.teal | close-account | we-flag/tealer-clean |
|  | app_1300027927.teal | close-asset | we-flag/tealer-clean |
|  | app_1300027927.teal | group-size | we-flag/tealer-clean |
|  | app_130875715.teal | close-account | we-flag/tealer-clean |
|  | app_130875715.teal | close-asset | we-flag/tealer-clean |
|  | app_130875715.teal | group-size | we-flag/tealer-clean |
|  | app_130881084.teal | close-account | we-flag/tealer-clean |
|  | app_130881084.teal | close-asset | we-flag/tealer-clean |
|  | app_130881084.teal | group-size | we-flag/tealer-clean |
|  | app_130883712.teal | close-account | we-flag/tealer-clean |
|  | app_130883712.teal | close-asset | we-flag/tealer-clean |
|  | app_130883712.teal | group-size | we-flag/tealer-clean |
|  | app_131401197.teal | close-account | we-flag/tealer-clean |
|  | app_131401197.teal | close-asset | we-flag/tealer-clean |
|  | app_131401197.teal | group-size | we-flag/tealer-clean |
|  | app_131416223.teal | close-account | we-flag/tealer-clean |
|  | app_131416223.teal | close-asset | we-flag/tealer-clean |
|  | app_131416223.teal | group-size | we-flag/tealer-clean |
|  | app_131458516.teal | close-account | we-flag/tealer-clean |
|  | app_131458516.teal | close-asset | we-flag/tealer-clean |
|  | app_131458516.teal | group-size | we-flag/tealer-clean |
|  | app_131602588.teal | close-account | we-flag/tealer-clean |
|  | app_131602588.teal | close-asset | we-flag/tealer-clean |
|  | app_131602588.teal | group-size | we-flag/tealer-clean |
|  | app_132262799.teal | close-account | we-flag/tealer-clean |
|  | app_132262799.teal | close-asset | we-flag/tealer-clean |
|  | app_132262799.teal | group-size | we-flag/tealer-clean |
|  | app_132882744.teal | close-account | we-flag/tealer-clean |
|  | app_132882744.teal | close-asset | we-flag/tealer-clean |
|  | app_132882744.teal | group-size | we-flag/tealer-clean |
|  | app_132887832.teal | close-account | we-flag/tealer-clean |
|  | app_132887832.teal | close-asset | we-flag/tealer-clean |
|  | app_132887832.teal | group-size | we-flag/tealer-clean |
|  | app_133971086.teal | close-account | we-flag/tealer-clean |
|  | app_133971086.teal | close-asset | we-flag/tealer-clean |
|  | app_133971086.teal | group-size | we-flag/tealer-clean |
|  | app_135740090.teal | close-account | we-flag/tealer-clean |
|  | app_135740090.teal | close-asset | we-flag/tealer-clean |
|  | app_135740090.teal | group-size | we-flag/tealer-clean |
|  | app_137118354.teal | close-account | we-flag/tealer-clean |
|  | app_137118354.teal | close-asset | we-flag/tealer-clean |
|  | app_137118354.teal | group-size | we-flag/tealer-clean |
|  | app_137447190.teal | close-account | we-flag/tealer-clean |
|  | app_137447190.teal | close-asset | we-flag/tealer-clean |
|  | app_137447190.teal | group-size | we-flag/tealer-clean |
|  | app_137491307.teal | deletable | we-flag/tealer-clean |
|  | app_137491307.teal | updatable | we-flag/tealer-clean |
|  | app_137491307.teal | close-account | we-flag/tealer-clean |
|  | app_137491307.teal | close-asset | we-flag/tealer-clean |
|  | app_137491307.teal | group-size | we-flag/tealer-clean |
|  | app_1600491197.teal | deletable | we-flag/tealer-clean |
|  | app_1600491197.teal | updatable | we-flag/tealer-clean |
|  | app_1600491197.teal | rekey | we-flag/tealer-clean |
|  | app_1600491197.teal | close-account | we-flag/tealer-clean |
|  | app_1600491197.teal | close-asset | we-flag/tealer-clean |
|  | app_1600491197.teal | fee | we-flag/tealer-clean |
|  | app_1600493488.teal | deletable | we-flag/tealer-clean |
|  | app_1600493488.teal | updatable | we-flag/tealer-clean |
|  | app_1600493488.teal | rekey | we-flag/tealer-clean |
|  | app_1600493488.teal | close-account | we-flag/tealer-clean |
|  | app_1600493488.teal | close-asset | we-flag/tealer-clean |
|  | app_1600493488.teal | fee | we-flag/tealer-clean |
|  | app_1600493618.teal | deletable | we-flag/tealer-clean |
|  | app_1600493618.teal | updatable | we-flag/tealer-clean |
|  | app_1600493618.teal | rekey | we-flag/tealer-clean |
|  | app_1600493618.teal | close-account | we-flag/tealer-clean |
|  | app_1600493618.teal | close-asset | we-flag/tealer-clean |
|  | app_1600493618.teal | fee | we-flag/tealer-clean |
|  | app_1600495627.teal | deletable | we-flag/tealer-clean |
|  | app_1600495627.teal | updatable | we-flag/tealer-clean |
|  | app_1600495627.teal | rekey | we-flag/tealer-clean |
|  | app_1600495627.teal | close-account | we-flag/tealer-clean |
|  | app_1600495627.teal | close-asset | we-flag/tealer-clean |
|  | app_1600495627.teal | fee | we-flag/tealer-clean |
|  | app_1600495962.teal | deletable | we-flag/tealer-clean |
|  | app_1600495962.teal | updatable | we-flag/tealer-clean |
|  | app_1600495962.teal | rekey | we-flag/tealer-clean |
|  | app_1600495962.teal | close-account | we-flag/tealer-clean |
|  | app_1600495962.teal | close-asset | we-flag/tealer-clean |
|  | app_1600495962.teal | fee | we-flag/tealer-clean |
|  | app_1600496167.teal | deletable | we-flag/tealer-clean |
|  | app_1600496167.teal | updatable | we-flag/tealer-clean |
|  | app_1600496167.teal | rekey | we-flag/tealer-clean |
|  | app_1600496167.teal | close-account | we-flag/tealer-clean |
|  | app_1600496167.teal | close-asset | we-flag/tealer-clean |
|  | app_1600496167.teal | fee | we-flag/tealer-clean |
|  | app_1600496224.teal | deletable | we-flag/tealer-clean |
|  | app_1600496224.teal | updatable | we-flag/tealer-clean |
|  | app_1600496224.teal | rekey | we-flag/tealer-clean |
|  | app_1600496224.teal | close-account | we-flag/tealer-clean |
|  | app_1600496224.teal | close-asset | we-flag/tealer-clean |
|  | app_1600496224.teal | fee | we-flag/tealer-clean |
|  | app_177244932.teal | deletable | we-flag/tealer-clean |
|  | app_177244932.teal | close-account | we-flag/tealer-clean |
|  | app_177244932.teal | close-asset | we-flag/tealer-clean |
|  | app_177244932.teal | group-size | we-flag/tealer-clean |
|  | app_177535159.teal | close-account | we-flag/tealer-clean |
|  | app_177535159.teal | close-asset | we-flag/tealer-clean |
|  | app_177535159.teal | group-size | we-flag/tealer-clean |
|  | app_177623021.teal | close-account | we-flag/tealer-clean |
|  | app_177623021.teal | close-asset | we-flag/tealer-clean |
|  | app_177623021.teal | group-size | we-flag/tealer-clean |
|  | app_177629935.teal | close-account | we-flag/tealer-clean |
|  | app_177629935.teal | close-asset | we-flag/tealer-clean |
|  | app_177629935.teal | group-size | we-flag/tealer-clean |
|  | app_177634838.teal | close-account | we-flag/tealer-clean |
|  | app_177634838.teal | close-asset | we-flag/tealer-clean |
|  | app_177634838.teal | group-size | we-flag/tealer-clean |
|  | app_177686957.teal | close-account | we-flag/tealer-clean |
|  | app_177686957.teal | close-asset | we-flag/tealer-clean |
|  | app_177686957.teal | group-size | we-flag/tealer-clean |
|  | app_177775506.teal | close-account | we-flag/tealer-clean |
|  | app_177775506.teal | close-asset | we-flag/tealer-clean |
|  | app_177775506.teal | group-size | we-flag/tealer-clean |
|  | app_180035126.teal | close-account | we-flag/tealer-clean |
|  | app_180035126.teal | close-asset | we-flag/tealer-clean |
|  | app_180035126.teal | group-size | we-flag/tealer-clean |
|  | app_180158986.teal | close-account | we-flag/tealer-clean |
|  | app_180158986.teal | close-asset | we-flag/tealer-clean |
|  | app_180158986.teal | group-size | we-flag/tealer-clean |
|  | app_180221107.teal | close-account | we-flag/tealer-clean |
|  | app_180221107.teal | close-asset | we-flag/tealer-clean |
|  | app_180221107.teal | group-size | we-flag/tealer-clean |
|  | app_180948843.teal | close-account | we-flag/tealer-clean |
|  | app_180948843.teal | close-asset | we-flag/tealer-clean |
|  | app_180948843.teal | group-size | we-flag/tealer-clean |
|  | app_181541402.teal | close-account | we-flag/tealer-clean |
|  | app_181541402.teal | close-asset | we-flag/tealer-clean |
|  | app_181541402.teal | group-size | we-flag/tealer-clean |
|  | app_182833351.teal | close-account | we-flag/tealer-clean |
|  | app_182833351.teal | close-asset | we-flag/tealer-clean |
|  | app_182833351.teal | group-size | we-flag/tealer-clean |
|  | app_1900079716.teal | updatable | we-flag/tealer-clean |
|  | app_1900079716.teal | close-asset | we-flag/tealer-clean |
|  | app_1900079716.teal | group-size | we-flag/tealer-clean |
|  | app_1900092936.teal | deletable | we-flag/tealer-clean |
|  | app_1900092936.teal | updatable | we-flag/tealer-clean |
|  | app_1900092936.teal | close-account | we-flag/tealer-clean |
|  | app_1900092936.teal | close-asset | we-flag/tealer-clean |
|  | app_200447316.teal | close-account | we-flag/tealer-clean |
|  | app_200447316.teal | close-asset | we-flag/tealer-clean |
|  | app_200447316.teal | group-size | we-flag/tealer-clean |
|  | app_203103308.teal | deletable | we-flag/tealer-clean |
|  | app_203103308.teal | updatable | we-flag/tealer-clean |
|  | app_203103308.teal | close-account | we-flag/tealer-clean |
|  | app_203103308.teal | close-asset | we-flag/tealer-clean |
|  | app_203103308.teal | group-size | we-flag/tealer-clean |
|  | app_203103408.teal | deletable | we-flag/tealer-clean |
|  | app_203103408.teal | updatable | we-flag/tealer-clean |
|  | app_203103408.teal | close-account | we-flag/tealer-clean |
|  | app_203103408.teal | close-asset | we-flag/tealer-clean |
|  | app_203103408.teal | group-size | we-flag/tealer-clean |
|  | app_203122300.teal | close-account | we-flag/tealer-clean |
|  | app_203122300.teal | close-asset | we-flag/tealer-clean |
|  | app_203122300.teal | group-size | we-flag/tealer-clean |
|  | app_203122411.teal | close-account | we-flag/tealer-clean |
|  | app_203122411.teal | close-asset | we-flag/tealer-clean |
|  | app_203122411.teal | group-size | we-flag/tealer-clean |
|  | app_203122500.teal | close-account | we-flag/tealer-clean |
|  | app_203122500.teal | close-asset | we-flag/tealer-clean |
|  | app_203122500.teal | group-size | we-flag/tealer-clean |
|  | app_203122583.teal | close-account | we-flag/tealer-clean |
|  | app_203122583.teal | close-asset | we-flag/tealer-clean |
|  | app_203122583.teal | group-size | we-flag/tealer-clean |
|  | app_203122637.teal | close-account | we-flag/tealer-clean |
|  | app_203122637.teal | close-asset | we-flag/tealer-clean |
|  | app_203122637.teal | group-size | we-flag/tealer-clean |
|  | app_203122713.teal | close-account | we-flag/tealer-clean |
|  | app_203122713.teal | close-asset | we-flag/tealer-clean |
|  | app_203122713.teal | group-size | we-flag/tealer-clean |
|  | app_2200042961.teal | close-account | we-flag/tealer-clean |
|  | app_2200042961.teal | close-asset | we-flag/tealer-clean |
|  | app_2200042961.teal | group-size | we-flag/tealer-clean |
|  | app_2200060952.teal | deletable | we-flag/tealer-clean |
|  | app_2200060952.teal | updatable | we-flag/tealer-clean |
|  | app_2200060952.teal | close-account | we-flag/tealer-clean |
|  | app_2200060952.teal | close-asset | we-flag/tealer-clean |
|  | app_2200060952.teal | group-size | we-flag/tealer-clean |
|  | app_2200131883.teal | deletable | we-flag/tealer-clean |
|  | app_2200131883.teal | updatable | we-flag/tealer-clean |
|  | app_2200131883.teal | close-account | we-flag/tealer-clean |
|  | app_2200131883.teal | close-asset | we-flag/tealer-clean |
|  | app_2200131883.teal | group-size | we-flag/tealer-clean |
|  | app_2200141294.teal | close-account | we-flag/tealer-clean |
|  | app_2200141294.teal | close-asset | we-flag/tealer-clean |
|  | app_2200141294.teal | group-size | we-flag/tealer-clean |
|  | app_2200145651.teal | close-account | we-flag/tealer-clean |
|  | app_2200145651.teal | close-asset | we-flag/tealer-clean |
|  | app_2200145651.teal | group-size | we-flag/tealer-clean |
|  | app_2200606875.teal | deletable | we-flag/tealer-clean |
|  | app_2200606875.teal | updatable | we-flag/tealer-clean |
|  | app_2200606875.teal | close-account | we-flag/tealer-clean |
|  | app_2200606875.teal | close-asset | we-flag/tealer-clean |
|  | app_2200606875.teal | group-size | we-flag/tealer-clean |
|  | app_2200608153.teal | deletable | we-flag/tealer-clean |
|  | app_2200608153.teal | close-account | we-flag/tealer-clean |
|  | app_2200608153.teal | close-asset | we-flag/tealer-clean |
|  | app_2200608153.teal | group-size | we-flag/tealer-clean |
|  | app_2200608887.teal | deletable | we-flag/tealer-clean |
|  | app_2200608887.teal | close-account | we-flag/tealer-clean |
|  | app_2200608887.teal | close-asset | we-flag/tealer-clean |
|  | app_2200608887.teal | group-size | we-flag/tealer-clean |
|  | app_2200609638.teal | deletable | we-flag/tealer-clean |
|  | app_2200609638.teal | close-account | we-flag/tealer-clean |
|  | app_2200609638.teal | close-asset | we-flag/tealer-clean |
|  | app_2200609638.teal | group-size | we-flag/tealer-clean |
|  | app_2500004531.teal | updatable | we-flag/tealer-clean |
|  | app_2500004531.teal | close-account | we-flag/tealer-clean |
|  | app_2500004531.teal | close-asset | we-flag/tealer-clean |
|  | app_2500004531.teal | group-size | we-flag/tealer-clean |
|  | app_2500034285.teal | updatable | we-flag/tealer-clean |
|  | app_2500034285.teal | close-account | we-flag/tealer-clean |
|  | app_2500034285.teal | close-asset | we-flag/tealer-clean |
|  | app_2500034285.teal | group-size | we-flag/tealer-clean |
|  | app_2500034389.teal | updatable | we-flag/tealer-clean |
|  | app_2500034389.teal | close-account | we-flag/tealer-clean |
|  | app_2500034389.teal | close-asset | we-flag/tealer-clean |
|  | app_2500034389.teal | group-size | we-flag/tealer-clean |
|  | app_2500046301.teal | updatable | we-flag/tealer-clean |
|  | app_2500046301.teal | close-account | we-flag/tealer-clean |
|  | app_2500046301.teal | close-asset | we-flag/tealer-clean |
|  | app_2500046301.teal | group-size | we-flag/tealer-clean |
|  | app_2500059016.teal | updatable | we-flag/tealer-clean |
|  | app_2500059016.teal | close-account | we-flag/tealer-clean |
|  | app_2500059016.teal | close-asset | we-flag/tealer-clean |
|  | app_2500059016.teal | group-size | we-flag/tealer-clean |
|  | app_2500131223.teal | updatable | we-flag/tealer-clean |
|  | app_2500131223.teal | close-account | we-flag/tealer-clean |
|  | app_2500131223.teal | close-asset | we-flag/tealer-clean |
|  | app_2500131223.teal | group-size | we-flag/tealer-clean |
|  | app_2500141757.teal | updatable | we-flag/tealer-clean |
|  | app_2500141757.teal | close-account | we-flag/tealer-clean |
|  | app_2500141757.teal | close-asset | we-flag/tealer-clean |
|  | app_2500141757.teal | group-size | we-flag/tealer-clean |
|  | app_2500447406.teal | close-account | we-flag/tealer-clean |
|  | app_2500447406.teal | close-asset | we-flag/tealer-clean |
|  | app_2500447406.teal | group-size | we-flag/tealer-clean |
|  | app_2500705413.teal | updatable | we-flag/tealer-clean |
|  | app_2500705413.teal | close-asset | we-flag/tealer-clean |
|  | app_2500705413.teal | group-size | we-flag/tealer-clean |
|  | app_2501001820.teal | deletable | we-flag/tealer-clean |
|  | app_2501001820.teal | updatable | we-flag/tealer-clean |
|  | app_2501001820.teal | close-account | we-flag/tealer-clean |
|  | app_2501001820.teal | close-asset | we-flag/tealer-clean |
|  | app_250179238.teal | updatable | we-flag/tealer-clean |
|  | app_250179238.teal | close-account | we-flag/tealer-clean |
|  | app_250179238.teal | close-asset | we-flag/tealer-clean |
|  | app_250268159.teal | close-account | we-flag/tealer-clean |
|  | app_250268159.teal | close-asset | we-flag/tealer-clean |
|  | app_250291933.teal | close-account | we-flag/tealer-clean |
|  | app_250291933.teal | close-asset | we-flag/tealer-clean |
|  | app_250620637.teal | updatable | we-flag/tealer-clean |
|  | app_250620637.teal | close-account | we-flag/tealer-clean |
|  | app_250620637.teal | close-asset | we-flag/tealer-clean |
|  | app_250622670.teal | updatable | we-flag/tealer-clean |
|  | app_250622670.teal | close-account | we-flag/tealer-clean |
|  | app_250622670.teal | close-asset | we-flag/tealer-clean |
|  | app_250726691.teal | updatable | we-flag/tealer-clean |
|  | app_250726691.teal | close-account | we-flag/tealer-clean |
|  | app_250726691.teal | close-asset | we-flag/tealer-clean |
|  | app_250738356.teal | updatable | we-flag/tealer-clean |
|  | app_250738356.teal | close-account | we-flag/tealer-clean |
|  | app_250738356.teal | close-asset | we-flag/tealer-clean |
|  | app_251406758.teal | updatable | we-flag/tealer-clean |
|  | app_251406758.teal | close-account | we-flag/tealer-clean |
|  | app_251406758.teal | close-asset | we-flag/tealer-clean |
|  | app_251513097.teal | updatable | we-flag/tealer-clean |
|  | app_251513097.teal | close-account | we-flag/tealer-clean |
|  | app_251513097.teal | close-asset | we-flag/tealer-clean |
|  | app_251807948.teal | close-account | we-flag/tealer-clean |
|  | app_251807948.teal | close-asset | we-flag/tealer-clean |
|  | app_251932073.teal | close-account | we-flag/tealer-clean |
|  | app_251932073.teal | close-asset | we-flag/tealer-clean |
|  | app_252270619.teal | updatable | we-flag/tealer-clean |
|  | app_252270619.teal | close-account | we-flag/tealer-clean |
|  | app_252270619.teal | close-asset | we-flag/tealer-clean |
|  | app_252345741.teal | updatable | we-flag/tealer-clean |
|  | app_252345741.teal | close-account | we-flag/tealer-clean |
|  | app_252345741.teal | close-asset | we-flag/tealer-clean |
|  | app_252623152.teal | updatable | we-flag/tealer-clean |
|  | app_252623152.teal | close-account | we-flag/tealer-clean |
|  | app_252623152.teal | close-asset | we-flag/tealer-clean |
|  | app_252844573.teal | updatable | we-flag/tealer-clean |
|  | app_252844573.teal | close-account | we-flag/tealer-clean |
|  | app_252844573.teal | close-asset | we-flag/tealer-clean |
|  | app_252863407.teal | close-account | we-flag/tealer-clean |
|  | app_252863407.teal | close-asset | we-flag/tealer-clean |
|  | app_3400287920.teal | close-account | we-flag/tealer-clean |
|  | app_3400287920.teal | close-asset | we-flag/tealer-clean |
|  | app_3400287920.teal | group-size | we-flag/tealer-clean |
|  | app_3550285020.teal | group-size | we-flag/tealer-clean |
|  | app_3550286646.teal | group-size | we-flag/tealer-clean |
|  | app_400058516.teal | updatable | we-flag/tealer-clean |
|  | app_400058516.teal | close-account | we-flag/tealer-clean |
|  | app_400058516.teal | close-asset | we-flag/tealer-clean |
|  | app_400121339.teal | updatable | we-flag/tealer-clean |
|  | app_400121339.teal | close-account | we-flag/tealer-clean |
|  | app_400121339.teal | close-asset | we-flag/tealer-clean |
|  | app_400173582.teal | updatable | we-flag/tealer-clean |
|  | app_400173582.teal | close-account | we-flag/tealer-clean |
|  | app_400173582.teal | close-asset | we-flag/tealer-clean |
|  | app_400179580.teal | updatable | we-flag/tealer-clean |
|  | app_400179580.teal | close-account | we-flag/tealer-clean |
|  | app_400179580.teal | close-asset | we-flag/tealer-clean |
|  | app_400181465.teal | updatable | we-flag/tealer-clean |
|  | app_400181465.teal | close-account | we-flag/tealer-clean |
|  | app_400181465.teal | close-asset | we-flag/tealer-clean |
|  | app_400207778.teal | updatable | we-flag/tealer-clean |
|  | app_400207778.teal | close-account | we-flag/tealer-clean |
|  | app_400207778.teal | close-asset | we-flag/tealer-clean |
|  | app_400259129.teal | updatable | we-flag/tealer-clean |
|  | app_400259129.teal | close-account | we-flag/tealer-clean |
|  | app_400259129.teal | close-asset | we-flag/tealer-clean |
|  | app_400373593.teal | updatable | we-flag/tealer-clean |
|  | app_400373593.teal | close-account | we-flag/tealer-clean |
|  | app_400373593.teal | close-asset | we-flag/tealer-clean |
|  | app_400387361.teal | updatable | we-flag/tealer-clean |
|  | app_400387361.teal | close-account | we-flag/tealer-clean |
|  | app_400387361.teal | close-asset | we-flag/tealer-clean |
|  | app_400405185.teal | updatable | we-flag/tealer-clean |
|  | app_400405185.teal | close-account | we-flag/tealer-clean |
|  | app_400405185.teal | close-asset | we-flag/tealer-clean |
|  | app_400420888.teal | updatable | we-flag/tealer-clean |
|  | app_400420888.teal | close-account | we-flag/tealer-clean |
|  | app_400420888.teal | close-asset | we-flag/tealer-clean |
|  | app_400427038.teal | updatable | we-flag/tealer-clean |
|  | app_400427038.teal | close-account | we-flag/tealer-clean |
|  | app_400427038.teal | close-asset | we-flag/tealer-clean |
|  | app_400434529.teal | updatable | we-flag/tealer-clean |
|  | app_400434529.teal | close-account | we-flag/tealer-clean |
|  | app_400434529.teal | close-asset | we-flag/tealer-clean |
|  | app_400440133.teal | updatable | we-flag/tealer-clean |
|  | app_400440133.teal | close-account | we-flag/tealer-clean |
|  | app_400440133.teal | close-asset | we-flag/tealer-clean |
|  | app_400440562.teal | updatable | we-flag/tealer-clean |
|  | app_400440562.teal | close-account | we-flag/tealer-clean |
|  | app_400440562.teal | close-asset | we-flag/tealer-clean |
|  | app_400451745.teal | updatable | we-flag/tealer-clean |
|  | app_400451745.teal | close-account | we-flag/tealer-clean |
|  | app_400451745.teal | close-asset | we-flag/tealer-clean |
|  | app_550068165.teal | updatable | we-flag/tealer-clean |
|  | app_550068165.teal | close-account | we-flag/tealer-clean |
|  | app_550068165.teal | close-asset | we-flag/tealer-clean |
|  | app_550070932.teal | updatable | we-flag/tealer-clean |
|  | app_550070932.teal | close-account | we-flag/tealer-clean |
|  | app_550070932.teal | close-asset | we-flag/tealer-clean |
|  | app_550071595.teal | updatable | we-flag/tealer-clean |
|  | app_550071595.teal | close-account | we-flag/tealer-clean |
|  | app_550071595.teal | close-asset | we-flag/tealer-clean |
|  | app_550072519.teal | updatable | we-flag/tealer-clean |
|  | app_550072519.teal | close-account | we-flag/tealer-clean |
|  | app_550072519.teal | close-asset | we-flag/tealer-clean |
|  | app_550074600.teal | updatable | we-flag/tealer-clean |
|  | app_550074600.teal | close-account | we-flag/tealer-clean |
|  | app_550074600.teal | close-asset | we-flag/tealer-clean |
|  | app_550081824.teal | updatable | we-flag/tealer-clean |
|  | app_550081824.teal | close-account | we-flag/tealer-clean |
|  | app_550081824.teal | close-asset | we-flag/tealer-clean |
|  | app_550083094.teal | updatable | we-flag/tealer-clean |
|  | app_550083094.teal | close-account | we-flag/tealer-clean |
|  | app_550083094.teal | close-asset | we-flag/tealer-clean |
|  | app_550122758.teal | updatable | we-flag/tealer-clean |
|  | app_550122758.teal | close-account | we-flag/tealer-clean |
|  | app_550122758.teal | close-asset | we-flag/tealer-clean |
|  | app_550134899.teal | updatable | we-flag/tealer-clean |
|  | app_550134899.teal | close-account | we-flag/tealer-clean |
|  | app_550134899.teal | close-asset | we-flag/tealer-clean |
|  | app_550149576.teal | updatable | we-flag/tealer-clean |
|  | app_550149576.teal | close-account | we-flag/tealer-clean |
|  | app_550149576.teal | close-asset | we-flag/tealer-clean |
|  | app_550209249.teal | deletable | we-flag/tealer-clean |
|  | app_550209249.teal | updatable | we-flag/tealer-clean |
|  | app_550209249.teal | close-account | we-flag/tealer-clean |
|  | app_550209249.teal | close-asset | we-flag/tealer-clean |
|  | app_550209249.teal | group-size | we-flag/tealer-clean |
|  | app_550223845.teal | updatable | we-flag/tealer-clean |
|  | app_550223845.teal | close-account | we-flag/tealer-clean |
|  | app_550223845.teal | close-asset | we-flag/tealer-clean |
|  | app_550243331.teal | updatable | we-flag/tealer-clean |
|  | app_550243331.teal | close-account | we-flag/tealer-clean |
|  | app_550243331.teal | close-asset | we-flag/tealer-clean |
|  | app_550255427.teal | updatable | we-flag/tealer-clean |
|  | app_550255427.teal | close-account | we-flag/tealer-clean |
|  | app_550255427.teal | close-asset | we-flag/tealer-clean |
|  | app_550263704.teal | updatable | we-flag/tealer-clean |
|  | app_550263704.teal | close-account | we-flag/tealer-clean |
|  | app_550263704.teal | close-asset | we-flag/tealer-clean |
|  | app_550289580.teal | updatable | we-flag/tealer-clean |
|  | app_550289580.teal | close-account | we-flag/tealer-clean |
|  | app_550289580.teal | close-asset | we-flag/tealer-clean |
|  | app_60553466.teal | close-account | we-flag/tealer-clean |
|  | app_60553466.teal | close-asset | we-flag/tealer-clean |
|  | app_60553466.teal | group-size | we-flag/tealer-clean |
|  | app_60656593.teal | close-account | we-flag/tealer-clean |
|  | app_60656593.teal | close-asset | we-flag/tealer-clean |
|  | app_60656593.teal | group-size | we-flag/tealer-clean |
|  | app_60699511.teal | close-account | we-flag/tealer-clean |
|  | app_60699511.teal | close-asset | we-flag/tealer-clean |
|  | app_60699511.teal | group-size | we-flag/tealer-clean |
|  | app_700002456.teal | updatable | we-flag/tealer-clean |
|  | app_700002456.teal | close-account | we-flag/tealer-clean |
|  | app_700002456.teal | close-asset | we-flag/tealer-clean |
|  | app_700002607.teal | updatable | we-flag/tealer-clean |
|  | app_700002607.teal | close-account | we-flag/tealer-clean |
|  | app_700002607.teal | close-asset | we-flag/tealer-clean |
|  | app_700003159.teal | updatable | we-flag/tealer-clean |
|  | app_700003159.teal | close-account | we-flag/tealer-clean |
|  | app_700003159.teal | close-asset | we-flag/tealer-clean |
|  | app_700004487.teal | updatable | we-flag/tealer-clean |
|  | app_700004487.teal | close-account | we-flag/tealer-clean |
|  | app_700004487.teal | close-asset | we-flag/tealer-clean |
|  | app_700004487.teal | group-size | we-flag/tealer-clean |
|  | app_700005127.teal | updatable | we-flag/tealer-clean |
|  | app_700005127.teal | close-account | we-flag/tealer-clean |
|  | app_700005127.teal | close-asset | we-flag/tealer-clean |
|  | app_700006791.teal | updatable | we-flag/tealer-clean |
|  | app_700006791.teal | close-account | we-flag/tealer-clean |
|  | app_700006791.teal | close-asset | we-flag/tealer-clean |
|  | app_700008784.teal | updatable | we-flag/tealer-clean |
|  | app_700008784.teal | close-account | we-flag/tealer-clean |
|  | app_700008784.teal | close-asset | we-flag/tealer-clean |
|  | app_700009729.teal | updatable | we-flag/tealer-clean |
|  | app_700009729.teal | close-account | we-flag/tealer-clean |
|  | app_700009729.teal | close-asset | we-flag/tealer-clean |
|  | app_700010779.teal | updatable | we-flag/tealer-clean |
|  | app_700010779.teal | close-account | we-flag/tealer-clean |
|  | app_700010779.teal | close-asset | we-flag/tealer-clean |
|  | app_700011091.teal | updatable | we-flag/tealer-clean |
|  | app_700011091.teal | close-account | we-flag/tealer-clean |
|  | app_700011091.teal | close-asset | we-flag/tealer-clean |
|  | app_700011552.teal | updatable | we-flag/tealer-clean |
|  | app_700011552.teal | close-account | we-flag/tealer-clean |
|  | app_700011552.teal | close-asset | we-flag/tealer-clean |
|  | app_700011915.teal | updatable | we-flag/tealer-clean |
|  | app_700011915.teal | close-account | we-flag/tealer-clean |
|  | app_700011915.teal | close-asset | we-flag/tealer-clean |
|  | app_80393163.teal | close-account | we-flag/tealer-clean |
|  | app_80393163.teal | close-asset | we-flag/tealer-clean |
|  | app_80393163.teal | group-size | we-flag/tealer-clean |
|  | app_80441171.teal | close-account | we-flag/tealer-clean |
|  | app_80441171.teal | close-asset | we-flag/tealer-clean |
|  | app_80441171.teal | group-size | we-flag/tealer-clean |
|  | app_80441567.teal | close-account | we-flag/tealer-clean |
|  | app_80441567.teal | close-asset | we-flag/tealer-clean |
|  | app_80441567.teal | group-size | we-flag/tealer-clean |
|  | app_80441806.teal | close-account | we-flag/tealer-clean |
|  | app_80441806.teal | close-asset | we-flag/tealer-clean |
|  | app_80441806.teal | group-size | we-flag/tealer-clean |
|  | app_80441968.teal | close-account | we-flag/tealer-clean |
|  | app_80441968.teal | close-asset | we-flag/tealer-clean |
|  | app_80441968.teal | group-size | we-flag/tealer-clean |
|  | app_80443063.teal | close-account | we-flag/tealer-clean |
|  | app_80443063.teal | close-asset | we-flag/tealer-clean |
|  | app_80443063.teal | group-size | we-flag/tealer-clean |
|  | app_80444171.teal | close-account | we-flag/tealer-clean |
|  | app_80444171.teal | close-asset | we-flag/tealer-clean |
|  | app_80444171.teal | group-size | we-flag/tealer-clean |
|  | app_80444554.teal | close-account | we-flag/tealer-clean |
|  | app_80444554.teal | close-asset | we-flag/tealer-clean |
|  | app_80444554.teal | group-size | we-flag/tealer-clean |
|  | app_80444707.teal | close-account | we-flag/tealer-clean |
|  | app_80444707.teal | close-asset | we-flag/tealer-clean |
|  | app_80444707.teal | group-size | we-flag/tealer-clean |
|  | app_80445034.teal | close-account | we-flag/tealer-clean |
|  | app_80445034.teal | close-asset | we-flag/tealer-clean |
|  | app_80445034.teal | group-size | we-flag/tealer-clean |
|  | app_84226112.teal | close-account | we-flag/tealer-clean |
|  | app_84226112.teal | close-asset | we-flag/tealer-clean |
|  | app_84226112.teal | group-size | we-flag/tealer-clean |
|  | app_84226549.teal | close-account | we-flag/tealer-clean |
|  | app_84226549.teal | close-asset | we-flag/tealer-clean |
|  | app_84226549.teal | group-size | we-flag/tealer-clean |
|  | app_84226954.teal | close-account | we-flag/tealer-clean |
|  | app_84226954.teal | close-asset | we-flag/tealer-clean |
|  | app_84226954.teal | group-size | we-flag/tealer-clean |
|  | app_850011688.teal | updatable | we-flag/tealer-clean |
|  | app_850011688.teal | close-account | we-flag/tealer-clean |
|  | app_850011688.teal | close-asset | we-flag/tealer-clean |
|  | app_850011688.teal | group-size | we-flag/tealer-clean |
|  | app_850014122.teal | updatable | we-flag/tealer-clean |
|  | app_850014122.teal | close-account | we-flag/tealer-clean |
|  | app_850014122.teal | close-asset | we-flag/tealer-clean |
|  | app_850014122.teal | group-size | we-flag/tealer-clean |
|  | app_850020935.teal | updatable | we-flag/tealer-clean |
|  | app_850020935.teal | close-account | we-flag/tealer-clean |
|  | app_850020935.teal | close-asset | we-flag/tealer-clean |
|  | app_850020935.teal | group-size | we-flag/tealer-clean |
|  | app_90001028.teal | close-account | we-flag/tealer-clean |
|  | app_90001028.teal | close-asset | we-flag/tealer-clean |
|  | app_90001028.teal | group-size | we-flag/tealer-clean |
|  | app_90001334.teal | close-account | we-flag/tealer-clean |
|  | app_90001334.teal | close-asset | we-flag/tealer-clean |
|  | app_90001334.teal | group-size | we-flag/tealer-clean |
|  | app_91237257.teal | close-account | we-flag/tealer-clean |
|  | app_91237257.teal | close-asset | we-flag/tealer-clean |
|  | app_91237257.teal | group-size | we-flag/tealer-clean |
|  | app_91252795.teal | close-account | we-flag/tealer-clean |
|  | app_91252795.teal | close-asset | we-flag/tealer-clean |
|  | app_91252795.teal | group-size | we-flag/tealer-clean |
|  | app_91255035.teal | close-account | we-flag/tealer-clean |
|  | app_91255035.teal | close-asset | we-flag/tealer-clean |
|  | app_91255035.teal | group-size | we-flag/tealer-clean |
|  | app_91260893.teal | close-account | we-flag/tealer-clean |
|  | app_91260893.teal | close-asset | we-flag/tealer-clean |
|  | app_91260893.teal | group-size | we-flag/tealer-clean |
|  | app_91294585.teal | close-account | we-flag/tealer-clean |
|  | app_91294585.teal | close-asset | we-flag/tealer-clean |
|  | app_91294585.teal | group-size | we-flag/tealer-clean |
|  | app_91295884.teal | close-account | we-flag/tealer-clean |
|  | app_91295884.teal | close-asset | we-flag/tealer-clean |
|  | app_91295884.teal | group-size | we-flag/tealer-clean |
|  | app_91297150.teal | close-account | we-flag/tealer-clean |
|  | app_91297150.teal | close-asset | we-flag/tealer-clean |
|  | app_91297150.teal | group-size | we-flag/tealer-clean |
|  | app_91298914.teal | close-account | we-flag/tealer-clean |
|  | app_91298914.teal | close-asset | we-flag/tealer-clean |
|  | app_91298914.teal | group-size | we-flag/tealer-clean |
|  | app_91302276.teal | close-account | we-flag/tealer-clean |
|  | app_91302276.teal | close-asset | we-flag/tealer-clean |
|  | app_91302276.teal | group-size | we-flag/tealer-clean |
|  | app_91305762.teal | close-account | we-flag/tealer-clean |
|  | app_91305762.teal | close-asset | we-flag/tealer-clean |
|  | app_91305762.teal | group-size | we-flag/tealer-clean |
|  | app_91842598.teal | close-account | we-flag/tealer-clean |
|  | app_91842598.teal | close-asset | we-flag/tealer-clean |
|  | app_91842598.teal | group-size | we-flag/tealer-clean |
|  | app_91858755.teal | close-account | we-flag/tealer-clean |
|  | app_91858755.teal | close-asset | we-flag/tealer-clean |
|  | app_91858755.teal | group-size | we-flag/tealer-clean |
|  | app_91954497.teal | close-account | we-flag/tealer-clean |
|  | app_91954497.teal | close-asset | we-flag/tealer-clean |
|  | app_91954497.teal | group-size | we-flag/tealer-clean |
|  | app_91968952.teal | close-account | we-flag/tealer-clean |
|  | app_91968952.teal | close-asset | we-flag/tealer-clean |
|  | app_91968952.teal | group-size | we-flag/tealer-clean |

</details>
