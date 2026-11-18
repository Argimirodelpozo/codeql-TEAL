# TealQL review: static analysis and decompilation

Reviewed revision `aa2eaa87`, 2026-11-18. This review is independent of [the ASTRA62 review](STATIC_ANALYSIS_AND_DECOMPILATION_REVIEW_ASTRA62.md) and does not repeat its five findings; section 8 says how the two relate.

## 1. Summary

The substrate is in good shape: all 1,019 mainnet probe programs parse with no diagnostics, the opcode tables match the AVM for v1 to v12, and 227 of the 231 distinct probes lift to TEAL deterministically. The problems are concentrated in four places, and they matter because each one produces a confident wrong answer with no warning.

1. **The detectors' model of "approval" and "guard" is too narrow.** A program that ends without `return` has no approval exit, so most detectors print nothing (A1). A guard written as the returned value is not seen, so the classic `c1 && c2; return` contract is reported as checking nothing (A2). In the other direction, any enforced comparison that mentions a field counts as validating it, including inverted, tautological and attacker-controlled ones (A3), and any state read counts as a trusted authority (A4).
2. **Unknown values can be erased from SSA and replaced by a definite wrong one.** A phi with one refused arm folds to the surviving arm's constant; three related shapes do the same. `health()` reports these programs as complete (A5 to A8). All four need hand-written or adversarial TEAL, which is exactly what an evasion looks like.
3. **The recompiled TEAL drops behaviour.** Puya's optimiser, which the lift borrows, deletes may-fail operations whose result is popped. On the corpus, 46 such guard sites in 11 programs go in and none come out, including minimum-output checks in a real AMM (D1). The same borrowed optimiser deletes a state write that an inner call could observe (D2) and causes the only four lift refusals on the corpus (D3). Removing two passes fixes all three.
4. **The CI gate can fail open.** The baseline fingerprint ignores line numbers and stores a set, so one accepted finding hides every later finding of the same rule in that file (P1). A directory target is merged into one program by ten subcommands, which loses findings (P2).

Seventy-four findings were raised and each was then checked by a second reviewer whose job was to refute it. None was refuted outright: 54 were confirmed, 18 were narrowed or corrected, and 2 turned out to be documented design choices. Severity was lowered on 29. The text below uses the corrected statements and severities.

### How this was done

Seven reviewers each took one subsystem, wrote small TEAL programs and ran the tool on them and on `tests/mainnet-random-probes`. A separate verifier per subsystem then reran every reproduction, checked the claimed AVM behaviour against a local go-algorand checkout and `goal clerk compile`, and looked for the behaviour in the existing docs and tests. Everything ran locally. No algod dryrun was run, so claims about lifted programs rest on reading the emitted TEAL against AVM semantics, not on execution. Timings were taken on a loaded workstation and are indicative only.

Severity reflects the verified impact: **high** is a wrong result on a shape that real or evasive code uses, **medium** needs an unusual shape or affects a secondary output, **low** is narrow or cosmetic. "Corpus" means the 1,019 files (231 distinct programs) in `tests/mainnet-random-probes`.

## 2. What is solid

These held up under attempts to break them, and the recommendations below build on them.

- **Front end.** Byte-literal decoding matched the reference assembler on every form tried. Unknown opcodes are a refusal, not a silent no-op. Parse degradation is carried on the graph and shown, with `--strict` to make it fatal.
- **Stack simulation.** One simulator serves both SSA and the lift. A differential fuzzer written for this review compared about 2 million executed operands against `Assignment.inputs`: 800 consistent-arity legacy programs had no mismatches, and 800 proto programs had 3, all traced to A5 and A6.
- **Value analysis.** Overflow, underflow, division by zero and out-of-range byte operations are never folded when the result is used. Canonical SSA is immutable and analyses work on revision-keyed copies, so detectors cannot change each other's results.
- **Path predicates.** `&&` is decomposed only on the true side and `||` only on the false side; irreducible flow is handled and labelled.
- **App lifecycle detectors.** Sender compared with an argument, an unpinned `gtxn 0 Sender`, an inverted `!=; assert`, `guard || other`, a dropped comparison and `switch` routing on OnCompletion all got the right verdict.
- **Lifted taint.** One transfer kernel; unresolved values are a first-class label that reaches sinks. Taint through `proto`/`frame_dig`, scratch across `callsub` and dynamic `loads`/`stores` was found in every probe.
- **Type recovery.** The confident tier only writes types that the layout forces, and no wrong type was found in it on a ground-truth contract. Storage-schema key discovery found all keys and prefixes on that contract with the right kind.
- **Budget model.** Costs are intervals that never claim a dynamic cost is exact, and the cost tables match go-algorand.
- **Engineering.** A written exit-code contract honoured on every expected error path, a mainnet findings ratchet, mutation gates that check the mutation landed, a layering test, and `HAZARD` comments that record the bug behind each rule.

## 3. Static analysis findings

### A1. A program that ends without `return` has no approval exit (high)

[`cfg/exits.py:37-44`](../src/tealql/tealtools/cfg/exits.py) requires the last op to be `return`. The AVM also ends a program when execution runs off the end, approving on a single non-zero value; before v2 this is the only way to approve. `CFG.exits`, `SSAProgram.off_end_exits` and the lift already model that exit, but `approving_exits` in [`path_predicates.py:414-426`](../src/tealql/tealtools/cfg/path_predicates.py) and [`_program_shape.py:44-53`](../src/tealql/security/_program_shape.py), [`cfg/group.py`](../src/tealql/tealtools/cfg/group.py) and `budget/advanced.py` do not.

Evidence: `tests/mainnet-random-probes/app_900088919.teal` is `#pragma version 4` followed by `pushint 1`, so anyone can update or delete it. `tealql detections --all --mode app` prints no findings. With a redundant trailing `return` it prints five (is-deletable, is-updatable, unprotected-deletable, unprotected-updatable, delete-funds-check). The PyTeal layout `int 1; b end ... end:` behaves the same way. Three corpus programs are affected; no fixture under `tests/` has this shape.

Fix: classify exits by terminal, not by opcode. Add `exit_value(prog, bb)` that returns the approval operand for an explicit `return`, for a block with no successors that does not end in `return`/`err`/`retsub`, and for a block in `prog.off_end_exits`, and use it at every call site above. Also emit a `no-approval-exit` notification when a non-empty program has none. Regression: for every fixture, findings must be identical with and without a redundant trailing `return`.

### A2. The value consumed by `return` is not a guard (high)

`_edge_predicates` ([`path_predicates.py:581-618`](../src/tealql/tealtools/cfg/path_predicates.py)) derives facts only from `assert`, `bz`/`bnz` and `switch`/`match`, and the enforcement walks in [`_enforcement.py:268-320`](../src/tealql/security/_enforcement.py), [`_field_protection.py:48-90`](../src/tealql/security/_field_protection.py) and [`_action_guards.py`](../src/tealql/security/_action_guards.py) accept only `assert` or a reject-gating branch as the consumer. An approving exit implies the returned value is non-zero, and that fact is never used.

Evidence: this logic signature checks every field and is reported for close-remainder-to, fee-validation, group-size-check and rekey-to, while `group-shape` prints no constraints:

```teal
#pragma version 6
global GroupSize; int 2; ==
gtxn 0 TypeEnum; int pay; ==; &&
txn RekeyTo; global ZeroAddress; ==; &&
txn Fee; int 1000; <=; &&
txn CloseRemainderTo; global ZeroAddress; ==; &&
return
```

The same program written with `assert` gets none of those four findings. On the corpus, 18 of the 74 programs with a comparison directly before `return` change findings when rewritten to the assert form; `txn Sender; global CreatorAddress; ==; return` is reported as "deletable by anyone" (for example `app_1050135395` line 75).

Fix: treat `return v` as `assert v` followed by approval. Add `exit_predicates(bb) = bb_preds[bb] | decompose(exit_value(bb), taken=True)` and make `return` an enforcing consumer in both enforcement walks. Adding the predicates alone is not enough, because the field detectors use the SSA walk. `_creator_enforcing_bbs` matches only a comparison that feeds the sink directly, so it needs the `&&` decomposition as well. Do A1 and A2 together: they share `exit_value`.

### A3. A guard is credited because it mentions the value, not because it constrains it (high)

Three separate classifiers share this fault.

- **Field detectors.** `_field_enforcement_bbs` ([`_field_protection.py:86-132`](../src/tealql/security/_field_protection.py)) accepts any comparison or `!` with one operand flowing from the field. `RekeyTo != ZeroAddress; assert`, `RekeyTo == RekeyTo`, `Fee >= 0`, `RekeyTo == arg 0` and `Fee <= btoi(arg 1)` all silence rekey-to, close-remainder-to, fee-validation and tx-type-check. `GroupSize >= 1` clears group-size-check. The rekey-to README says the predicate "constrains RekeyTo to zero"; the code does not check that.
- **Fund-flow classifier.** `_classify` ([`lift/fund_flow.py:563-576`](../src/tealql/tealtools/lift/fund_flow.py)) sets `checks_input` as soon as a register from the sink's definition tree appears under a guaranteed assert. An opt-in or existence flag read from an attacker-chosen asset, a hash comparison, or a comparison against a second attacker value all make tainted-fund-flow silent and `taint-query --verify --precise` print "guarded". It also walks through non-boolean wrappers with the guarantee intact: `(x == A) | y`, `(x == A) + y`, `(x == A) == 0`, `(x == A) <= 1`, `(x == A) * 0` and `select` are all credited. For sources in `ApplicationArgs`, partial-tainted-fund-flow still reports these; for foreign `Accounts`/`Assets`/`Applications` sources nothing does.
- **`abi-audit`.** `abi_address_fund_flows` ([`lift/arc4_recovery.py:1002-1068`](../src/tealql/tealtools/lift/arc4_recovery.py)) marks every operand of any `==`/`!=` as compared and then extends that to every read of the same `ApplicationArgs` index anywhere in the program. A recipient is "guarded" after `assert to != ZeroAddress`, or because an unrelated method compares its own argument with the same index. It is wrong the other way too: a withdraw gated by `Sender == admin` is reported as unguarded.

`docs/AUDIT_2026-08-07.md` already lists "field-aware guard semantics" as P0 for the fund-flow classifier. This finding widens it to the field detectors and `abi-audit`, and adds the wrapper cases.

Fix: one policy, used by all three. Have the classifier return the *shape* of the guard (equality with a clean value, equality with state, upper bound, lower bound, exclusion, membership) and keep a table in `language/avm.py` that says which shapes are sufficient per field: identity fields need equality that holds on the approving path against a non-attacker operand; `Fee` and amounts need an upper bound against a constant or `MinTxnFee`; ids need equality with a constant or trusted state. Make the walk below an assert an allowlist (`&&`, `||`, `!`, copies, phis, the final comparison); any other operator drops the guarantee. Reject comparisons whose operands resolve to the same SSA value. Replace the `abi-audit` proxy with this classifier and print the credited guard. A small generator that builds condition expressions and evaluates them concretely would have found every wrapper case; see section 6.

### A4. State reads are trusted as authority without asking who can write them (high)

`_is_trusted_address` ([`_action_guards.py:55-79`](../src/tealql/security/_action_guards.py)) trusts the output of every `app_global_get`, `app_local_get` and `*_ex` read, and `_comparison_pins_sender` ([`fund_flow.py:505-544`](../src/tealql/tealtools/lift/fund_flow.py)) accepts `Sender == app_global_get("owner")` as a sender pin. A local `owner` that the caller sets at opt-in, a global `admin` with an unguarded setter, and a read of a foreign app's state where the caller chooses the app all pass as a creator guard. `tealql auth` does list the unguarded write, but no detector connects the two. Trusting a rotatable admin is a stated design choice; the missing writer check is not recorded anywhere.

Fix: a per-slot writer summary on the lifted IR. For every state or box write, record the normalised key (reuse storage-schema recovery) and the guard verdict of the value operand. A slot is attacker-writable if some write outside a creation path has no sender or creator guard. Refuse such a slot as a trust anchor, seed reads of it as a taint source, and trust an `_ex` read only when the app operand is the current application or a constant. This one fact also yields an "unprotected admin setter" detector and unlocks the Sender-keyed membership guard in A13.

### A5. A phi with an unknown arm folds to the surviving arm's constant (high)

A stack cell the simulator refused is `None`. `merge_value` ([`ssa/stacksim.py:784-790`](../src/tealql/tealtools/ssa/stacksim.py)) puts it in the phi without setting `partial`, `_collapse_phi_args_to_leaves` ([`ssa/ssa.py:712-768`](../src/tealql/tealtools/ssa/ssa.py)) drops it, and the single-source identity step (`ssa.py:931-940`) then gives the phi the other arm's constant. A reproduction returns `txn Fee` on chain while the tool reports `return (2)`; a second one reports `return (0)` for an update path that approves when `GroupSize != 2`, and both updatable detectors stay silent. `health(deep=True)` is clean. The simulator's own comment says "a phi that silently omits a path reads as clean to every may-analysis".

Fix: give "unknown" a representation in public SSA. A sentinel `Unknown(reason, line)` operand that fails every constant, range and length lookup is the clean version; a `Phi.incomplete` flag that the identity step and the fact passes respect is the small version.

### A6. Legacy arity inference ignores height conflicts at shared blocks (high)

`infer_legacy_arities` ([`cfg/subroutines.py:296-349`](../src/tealql/tealtools/cfg/subroutines.py)) keeps the first stack height seen for a block and tests divergence only across `retsub` blocks. A no-`proto` callee whose paths meet at different heights before one shared `retsub`, or whose loop pops on each iteration, gets one arity and is not marked divergent. The caller's operands after the call are then definite and wrong. A reproduction approves an update for `NumAppArgs != 0` while the tool reports `return (0)` and no updatable finding. The two-`retsub` form of the same program is handled correctly. No corpus program has this shape.

Fix: when the walk reaches a block at a different height, record a conflict and treat the subroutine exactly like a two-`retsub` divergent one; where the per-path shift cannot be computed, withdraw the caller residual and push explicit unknowns.

### A7. Unresolved operands are removed from `Assignment.inputs`, shifting positions (medium)

`_build_assignments` ([`ssa/ssa.py:799-802`](../src/tealql/tealtools/ssa/ssa.py)) filters out unresolved operands, so `inputs[0]` is no longer the top of stack, against the contract in `ssa/models.py:228-232`. A concrete wrong fact: with a refused call result as the buffer, `replace2 0` gets an exact byte length of 2 because [`_byte_lengths.py:156-158`](../src/tealql/tealtools/analysis/_byte_lengths.py) reads `inputs[-1]`. `dataflow/box.py:218-220` has the same unguarded index.

Fix: keep the arity with an explicit placeholder (the `Unknown` operand from A5) and add a corpus invariant: for every assignment outside call and frame ops, `len(inputs) == op_arity(op)[0]`.

### A8. `health()` says "complete" when operands were refused (medium)

`health_for` ([`diagnostics/health.py:45-79`](../src/tealql/tealtools/diagnostics/health.py)) reports parse diagnostics, unknown opcodes and, in deep mode, unknown scratch values. Operand refusals, divergent subroutines, unsafe callees and partial phis never reach it, though `ssa.relations` and the dump catalog already hold the counts.

Fix: one degradation ledger fed from the simulator, read by `health_for` and the CLI. Report actual refusals only. Do **not** report height-conflicted or depth-poisoned blocks as degradations: they occur in about 35% of real contracts where reads are still answered, and would make `--strict` unusable.

### A9. A subroutine that falls through into another call target (medium)

`pyblock_partition` ([`cfg/subroutines.py:505-516`](../src/tealql/tealtools/cfg/subroutines.py)) lets the first routine claim the second's entry, and the corrected return-point map then gives the first `callsub` no continuation. The block after it is owned by nobody and never simulated; the join after it sees one arm. A reproduction reports `return (3)` with clean health where the AVM returns 1 when `Fee != 0`. The fix needs both halves: keeping every `callsub` target as its own root does not help unless the continuation pairing changes too. At minimum, any reachable block missing from the ownership map must be a degradation and joins fed by it must not fold.

### A10. Path predicates leak between activations of a recursive subroutine (medium)

The analysis ([`path_predicates.py:498-575`](../src/tealql/tealtools/cfg/path_predicates.py)) is context-insensitive and keys facts on SSA values. In a recursive subroutine the parameter phi stands for several live activations, so a fact the inner call established flows over the `retsub` edge to the outer frame. A reproduction prints `phi == 0` after the recursive call returns and `tealql loops` reports "no reachable loops" for a loop that runs 100 times. It needs separate `retsub` blocks per return, which is how Puya lays out multiple returns; the PyTeal `itoa` shape is safe because its single `retsub` block merges the fact away.

Fix: on a `retsub` to return-target edge whose subroutine is in a call-graph cycle, keep only facts rooted in immutable `txn`/`global` fields.

### A11. `taint-query` uses a narrower source set than the detectors (high)

`avm.attacker_input_label` is the shared definition of a source, but four consumers keep private predicates that know only `ApplicationArgs` and logic-signature args: [`taint_query.py:76-82`](../src/tealql/tealtools/dataflow/taint_query.py), `group_taint_graph._attacker_sources`, `xcontract_taint_graph.cross_taint_findings` and `byte_taint._default_sources`. Default `taint-query` and `--verify` print "(no dangerous sinks)" for flows from foreign `Accounts`, `Assets`, `Applications` and `itxn LastLog` that `--precise` and the detectors report. On `app_550975361` the default prints nothing and `--verify --precise` lists five sinks. The module calls this layer an over-approximation.

Fix: delete the private predicates and route all four through `attacker_input_label`. Add a parametrised test over every label and a ratchet that coarse sinks are a superset of precise sinks on the corpus.

### A12. Sources that no layer has (medium)

`attacker_input_label` ([`language/avm.py:340-366`](../src/tealql/tealtools/language/avm.py)) omits `txn Note` / `gtxn i Note` and sibling scratch read with `gload`/`gloads`/`gloadss`. A value read from an unauthenticated sibling's scratch and used as an inner-payment receiver is reported by nothing. Add `TxnNote`, `SiblingScratch` and `SiblingCreatedID` labels, with a discharge rule: a dominating equality on the same sibling's `ApplicationID` against a constant or creator-set state clears the sibling labels.

### A13. Smaller analysis findings

| Id | Sev. | Finding | Fix |
|---|---|---|---|
| A13a | medium | `gtxnsa FIELD i` takes its group index from the stack, but `_input_key` ([`fund_flow.py:455-467`](../src/tealql/tealtools/lift/fund_flow.py)) keys by opcode and immediates, so a check on sibling 0's argument clears the same-numbered argument of sibling 1. A patch returning no key for `gtxns`/`gtxnsa` makes the CRITICAL and two HIGH findings appear. | Include the resolved constant index in the key; no key when it is not constant. |
| A13b | medium | Two standard authorisation idioms are false positives: `state[Sender] - amount` (underflow panics, so it bounds the amount) and a Sender-keyed membership check such as `box_len("admin_" ++ Sender)`. | Credit a subtraction only when the minuend is a state read keyed by the current Sender; credit membership only when A4's writer summary says the slot is not attacker-writable. |
| A13c | medium | `gtxn N Sender == CreatorAddress` on the app call's own pinned index is ignored (`_sender_trusted_cmp`, [`_action_guards.py:91-107`](../src/tealql/security/_action_guards.py)); `app_1600496224` is reported as updatable by anyone. | Accept signed-transaction Sender reads when the index pin holds at the guard block; also accept `GroupSize == 1` as the pin. |
| A13d | medium | Cross-contract argument bridging counts `itxn_field ApplicationArgs` in source order, not per path ([`intercontract/analysis.py:286-304`](../src/tealql/tealtools/intercontract/analysis.py)). With one push per branch arm, a constant on one arm becomes a false pin on argument 0 and the callee finding is suppressed. `gitxn*` is missing from the return bridge. | Forward dataflow of the push count per inner transaction; pin only when every path agrees. |
| A13e | medium | unvalidated-group-sibling rejects the `Receiver != app; bnz reject` pin (only `==` is accepted) and, when the program has any subroutine, falls back to whole-program existence: 229 of the 522 corpus files it can see run in that mode. Relative-index siblings are a documented miss that covers about 35% of the corpus. | Accept `!=` under reject polarity; key siblings as `abs:N` or `rel:k` using the existing `relative_slot`; walk calls through the super-CFG. |
| A13f | medium | No app-mode check that a credited sibling asset transfer pins `XferAsset` (the fake-asset deposit). asset-id-validation is logicsig-only while its README says "application & logicsig". | Extend unvalidated-group-sibling with a separate rule id; fix the README. |
| A13g | medium | `txn NumAccounts` is seeded with the range (0, 4) ([`avm.py:868`](../src/tealql/tealtools/language/avm.py)); current consensus allows 8. constant-condition reports `NumAccounts == 6` as never taken. | Set (0, 8), update `tests/test_range_seed.py:100`, and pin protocol limits against a vendored consensus snapshot. Key them by consensus version, not by `#pragma version`. |
| A13h | medium | Numbers are parsed as base 10; the assembler uses Go base 0. `int 010` is 8 on chain and 10 in the tool. `_imm_int` returns 0 on a parse error, so `uncover 0x2` is modelled as `uncover 0` and `path-predicates` prints a `Sender == CreatorAddress` guard the program does not contain. Hand-written source only. | One `parse_uint` with Go rules, driven by each opcode's immediate kinds; an unparseable immediate is a diagnostic, never 0. |
| A13i | medium | Value analysis leaves cheap facts unused: arithmetic is skipped unless both operands already have a range, `len` ignores byte-length facts, there is no `select` rule, ranges are refined by `assert` only and never by a branch edge, loop counters get no range. | Full-range default at uint64-forcing ops (at the call site, not in `_operand_range`); edge refinement exposed through `range_at`; widening for loop phis. |
| A13j | low | TypeEnum is capped at 6, so a guard at the 6/7 boundary is reported as vacuous and `int hb` has no value. `b==` is treated as byte identity in `predicates_contradict`, so two differently padded encodings of one number make a feasible edge infeasible. `substring3` is proven in bounds without checking `start <= end`. `const_fold` folds a concat over 4,096 bytes and `b`-comparisons over 64 bytes, which the AVM rejects. | One-line or small fixes; details in the per-area notes. |
| A13k | low | Five assembler-legal spellings are dropped with a diagnostic but the default mode still prints results for the altered program: `#define`, empty `switch`/`match`, `label: op` on one line, `$` in labels (bare `extract` is a documented choice). `int TMPL_X` is worse: it yields no assignment and **no** diagnostic, later operands shift, and `--strict` does not refuse. | Give `int TMPL_X` the same recovery as `pushint TMPL_X`; diagnose any opcode line that yields no node. |
| A13l | low | Implicit flows are not tracked: a receiver chosen by `bz` on an argument is silent while the `select` spelling is reported. Reasonable for a taint analysis, but undocumented and inconsistent. | Document it; an optional control-dependence label, kept separate and lower severity, scoped to one routed method. |
| A13m | low | unsafe-lsig-args calls a hash lock "zero security"; ordering and `!=` gates on an argument are not reported although the README lists them. group-size-check flags exits that never read a sibling. | Accurate message with lower severity for hashed args; path-scope group-size-check and require `==` or an upper bound. |

### A14. Performance of the analysis

- **Dominators are cubic** ([`cfg/dominance.py:13-43`](../src/tealql/tealtools/cfg/dominance.py)). Post-dominators run the same routine over successors, so the ordinary forward layout is the bad order: a valid program of 400 sequential `cond; bnz skip` blocks (4.7 KB assembled) costs 14 s in post-dominators and `detections --all` takes 33 s; 800 blocks take 142 s. A prototype using `networkx.immediate_dominators` with a virtual root returned identical results on every case tried.
- **The path-predicate worklist** (`path_predicates.py:531-570`) is LIFO, seeded in source order, with no de-duplication: 400,600 edge evaluations for about 1,200 edges on the same program. `edge_is_feasible` is uncached and `analyze_loops` asks for the same edges three times.
- **Phi arguments are flattened to transitive leaves**, which is quadratic: a 2,620-instruction program with 60 live slots builds 7.5 million phi arguments and takes about a minute end to end.

Real contracts are unaffected (about 1 s each). This matters when scanning untrusted on-chain programs in bulk, where one crafted contract stalls the run. There is no per-file time budget; add one.

## 4. Decompilation findings

### D1. The recompiled TEAL loses guards whose result is popped (high)

The lift is value-based: `pop` lowers to nothing ([`to_puya_ir.py:293-297`](../src/tealql/tealtools/lift/to_puya_ir.py)). `_opt_passes` (`to_puya_ir.py:754-778`) always runs Puya's `remove_unused_variables`, whose side-effect-free set includes operations that can fail: `+`, `-`, `*`, `/`, `btoi`, `extract*`, `txna`, `concat`, and also `balance`, `asset_holding_get` and `app_params_get`. In Puya's source language an unused failing operation is removable. In a decompiler it is the guard.

Evidence: `int 18446744073709551615; int 1; +; pop; int 1; return`, which always fails on chain, lifts to `pushint 1; return`. On the 231 distinct probes, 11 programs contain 46 `-; pop` or `*; pop` guard sites and none survive. In `app_1050021565` the remove-liquidity minimum checks at input lines 301 to 310 vanish with empty diagnostics. The mechanism is recorded in `tests/test_adversarial_totality.py:718-743` ("10 of 10 dryrun inputs diverged") but it is unfixed and contradicted by README line 76. Detectors are not affected; they read the pre-IR, which keeps the operation.

### D2. A state write is deleted when the same key is rewritten later (medium)

Puya's `constant_reads_and_unobserved_writes_elimination` treats only a non-pure subroutine call as a barrier. `itxn_submit` is not one, and neither is the program's own `app_global_get_ex`. A reentrancy lock set before an inner call and cleared after it loses the first write. A variant with no inner call changes the verdict: `put k 1`, read `k` through `app_global_get_ex` on the current app, assert it is 1, `put k 2` loses `put k 1`, so the recompiled program rejects where the original approves. The corpus has 85 such removals and none with a barrier between the writes, so this is latent.

### D3. The only lift refusals on the corpus come from the same pass (medium)

Four of 231 probes (four variants of one v4 auction template) fail with `incompatible types on assignment: source = (uint64), target = (account)`: the pass in D2 forwards a stored value typed by the `any -> uint64` placeholder into a read recovered as an account. `diagnostics/errors.py:86-88` says about 0.1% of mainnet contracts do not lift; the measured rate on distinct programs is 1.7%.

**Fix for D1 to D3.** Remove `remove_unused_variables` and `constant_reads_and_unobserved_writes_elimination` from `_opt_passes`. The verifier did this by monkeypatch: 231 of 231 probes lift, all 46 guard sites survive, output grows by about 2%, and 88 targeted lift tests pass. Then, as an optional size optimisation, add a TealQL-owned cleanup: dead-code removal that deletes only definitions that cannot fail, driven by one `can_fail` table in `language/avm.py`, and store-to-load forwarding that stops at `itxn_submit` and checks type equality. Regression: a corpus invariant that the multiset of may-fail operations is preserved from input to output.

### D4. `match` with runtime keys becomes an always-failing `switch` (medium)

When a key is not constant, `_control_match` ([`lift.py:1297-1335`](../src/tealql/tealtools/lift/lift.py)) falls through to `goto_nth undefined` over successor order. The backend emits `pushbytes ""; switch ...` with the arms in the wrong positions and the key computations removed. Nothing is logged. It fails closed and no corpus program has the shape. It is distinct from ASTRA62 item 3, which covers constant keys. Fix: lower a dynamic `match` as the ordered compare chain the AVM defines, and make any terminator with an undefined selector a refusal.

### D5. There is no fidelity verdict (medium)

`lift_to_teal` returns a string ([`backend.py:21-23`](../src/tealql/tealtools/lift/backend.py)); its optional `diagnostics` list receives only the errors Puya logs. A consumer cannot tell a faithful recompile from one where the lift padded with undefined values or Puya reported a type error. A program whose nested divergent subroutine approves when `NumAppArgs == 0` lifts to one that fails on that path, with only a logger warning. Fix: return a `LiftResult` with the TEAL, a `faithful` flag, a list of typed degradations with source lines, pass statistics, and input and output versions. Keep the default permissive with an opt-in `strict`, because `tests/test_adversarial_totality.py` requires every legal program to lift without raising. This absorbs ASTRA62 item 5.

### D6. Smaller lift findings

| Id | Sev. | Finding | Fix |
|---|---|---|---|
| D6a | low | `bitlen` is listed as uint64-only in `type_recovery.py:92-95` and `avm.py:762-764`; the AVM accepts bytes. A bytes constant wider than 8 bytes feeding `bitlen` is rewritten to its low 8 bytes as an integer, flipping an approving program to rejecting, and the pre-IR that detectors read carries the wrong value too. | Remove `bitlen` from both tables; restrict the coercion to the typed-zero placeholder. |
| D6b | low | Output is always `#pragma version 10` or higher with no notice. A v1 logic signature loses the protocol's minimum-version protection against rekeying; a v10 approval cannot pair with a pre-v6 clear program. | Record input and output versions and the known differences in the result. |
| D6c | medium | The behavioural dryrun gate (no args, each selector, one junk arg, empty state) rarely reaches code past argument decoding; it reports no divergences on a corpus that loses 46 guard sites. README line 76 overstates what is tested. The recompile gate samples 64 name-ordered probes and misses all four refusals in D3. | An algod-free equivalence gate in default CI: the ordered sequence of side-effect operations and the multiset of may-fail operations must match between input and output. |

### D7. Recovery and audit output

- **`box-audit` misses the canonical cross-user write (high).** [`box_recovery.py:420-491`](../src/tealql/tealtools/lift/box_recovery.py) fails for three independent reasons. One `arg == Sender` comparison anywhere suppresses the whole program. An `arc4.Address` argument used as `who.native` is a plain `bytes` register and is not recognised as an address, even though `assert len == 32` dominates it. Only a two-part concat with a constant left operand is inspected, so `prefix ++ addr ++ id` is never labelled. The first two are stated as deliberate precision choices in docstrings but appear in no user-facing doc. Fix: suppress per access, on a dominating comparison of that key's address component with Sender; feed dominating length asserts into the speculative tier; flatten nested concats.
- **Method attribution is wrong for one-selector-per-line routers (medium).** `method_line_ranges` ([`metadata/abi.py:253-271`](../src/tealql/tealtools/metadata/abi.py)) pairs each selector line with a dispatch op at most 7 lines below. On `tests/contracts/reti-crossfamily-phi/approval.teal` (TealScript, 34 served methods) it returns 2 ranges, one of them mapping `setTokenPayoutRatio` to another method's body, and marks 32 served methods "not routable". This breaks the function's own promise that an unrecognised shape yields no attribution. Fix: derive the selector-to-entry map from the lifted IR, where the dispatch is explicit, and keep the text scan for names only.
- **Storage schema (medium).** Composite keys come back as `bytes`; a left-nested concat loses the prefix; one prefixed map is emitted as two rows because the grouping key includes the key type. A `biguint` value is reported as confident `uint512`, but a byte-math result is a variable-length byte string, so a decoder trusting the schema reads the wrong width. The README claims composite tuple keys are recovered, which holds only for the `Sender ++ itob` shape under test.
- **ARC-56 ingestion (medium).** A nested anonymous struct field, which the spec allows, raises `TypeError` and gives a traceback from `methods --arc56` and `storage-schema --arc56`; in a scan the spec is silently ignored. Events, actions, `readonly` and bare actions are dropped.
- **A `// method "sig"` comment is trusted over the selector bytes on the same line (low).** Labels only; forward-hash and compare.

### D8. The decompiler as a product

What exists is a faithful IR: `python -m tealql.tealtools.lift` and `tealql dump --view repr.puya_ir` print Puya IR with `tmp%N` registers, hex state keys and `labelN` subroutines. The README says so, so this is a gap against the word "decompilation", not a defect. The gap, in order of value for effort:

1. **A `tealql lift` subcommand** with `--emit pre-ir|puya-ir|teal`, `--json`, `-o`, and exit codes for faithful, degraded and refused. Today there is no CLI path to recompiled TEAL, the module entry point exits 0 after a type error and gives a traceback on a missing file, and `pyproject.toml:35` refers to a `tealql lift` that does not exist.
2. **Router recovery from the IR.** `tealql methods` is empty for all 1,019 probes by documented design, since a selector hash cannot be reversed. But the selector set, the selector-to-entry mapping and the OnCompletion and create guards are explicit in the lifted IR and no command lists them. Emit unnamed rows with provenance, then name them by forward-hashing candidates from an ARC-56 spec or a bundled signature dictionary.
3. **Per-method signature inference.** Puya and TealScript validate every argument at method entry, so the decode prologue is a near-complete type witness. It also supplies the address evidence that `box-audit` lacks.
4. **Evidence records for recovered types.** A guess is currently a type and a boolean keyed by `id(Register)`, which is why `dump --view analysis.abi` prints `object#128599242524224`, different on each run. Record the idiom and the lines matched.
5. **Readable output.** Source-line comments in emitted TEAL, state keys named from the schema, methods named from the router table, then a structurer for `if`/`while` over the IR. Label the pseudo-code as non-authoritative; the IR stays the checked artefact.
6. **An offline bytecode front end.** Targets must be `.teal` source; the only bytecode route is algod over the network. A pure-Python disassembler from the opcode table the project already tracks would let `audit` work from cached programs.

## 5. Product and CI findings

### P1. The baseline hides new findings of the same rule in the same file (high)

`fingerprint` ([`security/suppress.py:22-27`](../src/tealql/security/suppress.py)) hashes rule, file and the message with every `:\d+` replaced; the baseline stores a set and `partition` tests membership. All per-exit findings of one rule in one file share one fingerprint. Rebuilt from scratch by two verifiers: after baselining one rekey-to finding, adding a new unguarded exit gives two HIGH findings and exit 1 without the baseline, and "(no findings)" with exit 0 with it. Line-insensitivity is intended and tested; the collision is not, and the existing test passes only because its findings have different messages.

Fix: fingerprint on a structural anchor (rule, file, a hash of the normalised instruction window around the anchor, the ABI method when known) and store a count per fingerprint so that N accepted findings never cover N+1. Emit the same value as SARIF `partialFingerprints`.

### P2. A directory target is merged into one program (high)

`_load` ([`cli/_common.py:118-129`](../src/tealql/cli/_common.py)) builds one `SSAProgram` from a directory, which the `HAZARD` comment on `_load_programs` a few lines below forbids. It is used by `all`, `auth`, `box-df`, `itxn-report`, `group-shape`, `group-layout`, `path-predicates`, `functional`, `cfg` and `taint-query`. `group-shape` on a three-file directory prints no constraints although one file alone gives `GroupSize == 3`; `all` reports 1 finding where the three per-file runs give 3. README line 40 advertises a directory target for every subcommand. Fix: route every per-program command through `_load_programs` and emit one section per file; keep the merged program only for `xcontract`, `group-taint` and `dump --group-member`.

### P3. Smaller product findings

| Id | Sev. | Finding | Fix |
|---|---|---|---|
| P3a | medium | Loop bounds under-credit v4 and v5 programs: `BudgetContext.application` ([`budget/context.py:126-132`](../src/tealql/tealtools/budget/context.py)) clamps credit to 700 below v5 and drops inner-call credit below v6. Pooling is a consensus flag, not a program-version property. The same 8-unit loop reports at most 87 iterations at v4 and 23,799 at v6, and `proven_over_budget` can emit a false infeasibility proof. `tests/test_budget.py:120-136` pins the wrong belief. | Remove the version gate; make a historical view an explicit opt-in. |
| P3b | medium | Expected input failures (malformed `--options`, `--baseline`, `--registry`; `dump` with no target; an unreadable file) end in a traceback with exit 1, the code reserved for findings. The wheel smoke job accepts exit 1, so it passes a crashing CLI. | Catch `OSError` and config errors as exit 2; a last-resort handler with a distinct code; make the smoke job assert no traceback. |
| P3c | medium | `tealql detections` never reads `det.degraded`, has no per-detector crash isolation, and its `--strict` does not refuse a degraded run; `detections-scan --strict` exits 2 on the same input. `--strict` in a scan stops at the first problem and prints nothing for the remaining files. Compiled bytecode or base64 in a `.teal` file gives 32 "(no findings)" sections and exit 0. | One shared detector runner (the loop exists four times with different behaviour); `--fail-on-degraded` that finishes the run and then exits non-zero; detect bytecode and say so. |
| P3d | medium | With default options every detector runs on every file, which is documented in code and tested but not in the README. On 20 mainnet apps, 796 of 1,393 findings (57%) come from the seven logicsig-only detectors. The opt-in `auto_mode` has its own false negative: a program with no app-only opcode is classed as a logic signature and loses is-updatable. | Default to proof-based scoping only: a program containing an app-only opcode cannot be a valid logic signature, so skip the logicsig-only detectors and say so; leave ambiguous programs unfiltered. |
| P3e | medium | Machine-readable output is inconsistent. `--json` is accepted and ignored by `functional` and `dump`; `loops --json <dir>` prints one document per program, which does not parse; there are three finding shapes; SARIF has paths relative to the scan root with no base id, no fingerprints and no tool version; there is no `--version`. | Reject `--json` where unsupported; one versioned envelope, introduced behind a key so existing consumers keep working. |
| P3f | medium | `tealql methods <dir>` builds full SSA for every file to run two regular expressions: 5 minutes and 4.5 GB peak on the corpus to print `[]`, against 1.65 s for the same calls over raw text. `_load_programs` returns a list, so every multi-file lifted command holds all programs. `detections-scan` keeps every program with a finding alive until rendering. | Read text for `methods`; make `_load_programs` a generator; normalise findings to plain data eagerly, which also allows `--jobs`. |
| P3g | medium | Reported precision is a fixture regression gate, as `docs/PRECISION.md` says. What it hides: every finding has confidence "high"; per-exit emission multiplies findings (27 + 27 on one app); is-deletable, unprotected-deletable and delete-funds-check fire together on the same exit 123 times; no detector is run on another detector's fixtures; the table shows 0 false negatives while a detector README documents a deliberate one. | A hand-labelled field benchmark of about 100 probes scored per finding; the full detector-by-fixture matrix; honest confidences; group findings per exit. |
| P3h | low | `tealql loops` prints "no reachable loops" for a program whose only iteration is recursion. The cost model knows about recursion but shows it only inside a reported loop. `callsub` has no depth limit in the AVM; the bound is budget and the 1,000-slot stack. | A recursive region, or at least a degradation line. |
| P3i | low | Cross-contract taint findings are computed but shown only by a dump view; `tealql xcontract` and `audit` never print them. | Add a section and a JSON key. |

## 6. Structural improvements

Most findings above are instances of a few missing pieces. Building these removes classes of bugs instead of single ones.

1. **One facts-at-exit layer for every detector.** `facts_at_exit(prog, exit)` returns the constraints that hold on the approving path: path predicates plus the exit's own return operand, with `&&` decomposed, sibling slots normalised, and each right-hand side tagged const, chain global, state or attacker. The field detectors ask "is the required fact present" against a per-field policy table. This is the common root of A1, A2, A3 and A13c, and the building blocks (`PathPredicateAnalysis`, `constraints_at`, `relative_slot`, `branch_reject_polarity`) exist.
2. **Slot-writer summaries.** Who can write each global, local or box key, under which guard. Closes A4, gates A13b, and yields an unprotected-setter detector.
3. **A first-class `Unknown` operand and one degradation ledger.** Closes A5, A7 and A8 and gives A9 somewhere to report. Use a sentinel object, not bare `None`.
4. **A TealQL-owned, effect-aware cleanup for the lift** in place of Puya's source-language assumptions (D1 to D3), and a `LiftResult` with a refusal taxonomy (D4, D5).
5. **One source and sink registry.** Sources have one definition with four bypasses (A11); sinks are split three ways. Add a drift test that no module defines its own.
6. **One detector runner** owning crash isolation, degradation capture, mode scoping and eager normalisation (P3c, P3d, P3f).
7. **Test oracles that do not share the authors' assumptions.** Every confirmed finding here is either a spelling variant of the same semantics or a definite-but-wrong value, and the current tests compare the tool with expectations written alongside it.
   - *Metamorphic detector tests*: rewrite each fixture in ways that keep its meaning (explicit or implicit return; `assert c` or `c; bz err` or `c; return`; `txn F` or pinned `gtxn N F`; inline or `callsub`; scratch round-trip) and require the same verdict.
   - *A concrete-execution oracle for SSA operands*: the fuzzer from this review found A5, A6, A7 and A9 within minutes. Validate its interpreter against the go-algorand `logic` package offline.
   - *A guard-expression generator* with a concrete evaluator as oracle for the fund-flow classifier (A3).
   - *An offline assembler differential using `goal clerk compile`*, which needs no node. The existing one is gated on a reachable algod and compares constants only. It would have caught A13h, the TypeEnum gap and every case in A13k.
   - *A recovery ground-truth benchmark*: contract source, compiled TEAL and ARC-56 committed together, scored as correct, coarse, missing or wrong per category. The repo has no such triple today, and every D7 finding would have been caught by it.
8. **Version-aware tables.** Nothing in the front end, CFG or detectors reads the program version. Generate an opcode minimum-version table from `puya.ir.avm_ops.AVMOp`, diagnose an opcode newer than the pragma, and keep protocol limits in one table tagged by consensus version.

### Detector classes with no coverage

Worth adding on existing infrastructure, most valuable first: missing domain separation for `ed25519verify_bare`, `ecdsa_verify` and `falcon_verify`, where the signed message does not include the application id or genesis hash (plain `ed25519verify` already binds the program hash); an inner transaction with no `Fee` set, so the app pays (inner-txn-fee flags only an explicit non-zero constant); an authorisation model that names the actual gate (asset holding, signature, caller app, sibling sender) instead of reporting "by anyone"; box minimum-balance funding (AUDIT item 9); and opt-in/close-out consistency across an approval and clear-state pair (AUDIT item 11).

Three candidates were considered and are not worth building. A reentrancy-callback detector has little to find, because the AVM forbids an app calling itself even indirectly. A relative group index that underflows only fails the caller's own transaction. A clear-state program that rejects does not block the clear.

## 7. Suggested order

| Step | Items | Effort | Why first |
|---|---|---|---|
| 1 | D1 to D3: drop the two Puya passes | S | Verified by patch; fixes the largest fidelity gap and all four corpus refusals. |
| 2 | P1 baseline fingerprint | M | The CI gate fails open today. |
| 3 | A1 and A2 with shared `exit_value` | M | Silent false negatives and loud false positives on the most common contract shape. |
| 4 | A11 source predicates; A13a; A13g; D6a; P3a | S each | Small, contained, each a wrong answer. |
| 5 | P2 directory merge; P3b; P3c runner | M | Makes the CLI safe to put in CI. |
| 6 | A5 to A8: `Unknown` operand and ledger | M | Closes the adversarial evasion shapes in SSA. |
| 7 | A3 guard policy, then A4 writer summaries | M, then L | The largest precision and soundness gain; needs step 3. |
| 8 | Metamorphic and differential test harnesses | M | Keeps steps 3, 6 and 7 from regressing. |
| 9 | `tealql lift`, `LiftResult`, router recovery | M to L | Turns the lift into a usable decompiler. |
| 10 | A14 dominators and worklist; per-file time budget | S to M | Needed before bulk scans of untrusted programs. |

Documentation to correct in the meantime: README line 76 (the lift is not verified identical for behaviour past argument decoding, and loses popped guards until step 1); the composite-key recovery claim; the directory-target claim; the unlisted default that logicsig detectors run on apps; `diagnostics/errors.py:86-88` (1.7% of distinct corpus programs do not lift, not 0.1%); `pyproject.toml:35`.

## 8. Relation to the ASTRA62 review

Its five findings were given to the reviewers as known and were not re-examined. Three findings here extend them: D5 is a broader form of its item 5 (backend repairs invisible to API consumers) and should absorb it; D6c overlaps its item 2 (dryrun verdicts) and adds an algod-free gate; D4 is a different `match` defect from its item 3 (runtime keys, not a default arm that is also a case). A13d sits beside its item 1 in `intercontract/analysis.py` and should be fixed in the same change.

## 9. Limits of this review

- No algod dryrun was run. Statements that a lifted program behaves differently come from the emitted TEAL and AVM semantics checked against go-algorand source.
- A1 to A10 were measured on the corpus where stated. A5, A6 and A9 have no corpus instance; they are evasion shapes, not shapes compilers emit.
- Exploitability of the extra unguarded sinks found on real contracts (for example in A3) was not assessed.
- The reproduction programs were written to a session scratch directory and are not in the repository. The inline examples and the fixes' regression notes are enough to recreate them; the proposed tests should carry them as fixtures.
- Not reviewed in depth: `viz/` rendering, `resource_demand.py`, and the `audit` chain-fetch path.
