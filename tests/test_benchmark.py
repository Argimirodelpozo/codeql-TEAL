"""Detector precision/recall benchmark — detector quality as a measured number.

A GROUND-TRUTH-labeled corpus under ``tests/benchmark/<detector>/{vuln,safe}/*.teal``:
a ``vuln`` case is a contract the detector SHOULD flag, a ``safe`` case one it
should NOT. The harness runs each registered detector against its cases and scores
precision / recall / F1 against that truth — so a detector change is measured, not
guessed, and known limitations surface as a number (e.g. tainted-fund-flow's
param-fed false-negative shows up as recall < 1.0).

See the table:   pytest tests/test_benchmark.py -s
"""
from dataclasses import dataclass
from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.security import DETECTORS

BENCH = Path(__file__).resolve().parent / "benchmark"


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _fires(detector: str, teal: Path) -> bool:
    """Does ``detector`` flag ``teal`` (>=1 finding)? The benchmark measures
    detector LOGIC on per-detector-curated fixtures; mode scoping (app vs
    logicsig) is a deployment concern declared in the detection-options config,
    not exercised here."""
    prog = SSAProgram(str(teal))
    prog.propagate_constants()
    return len(DETECTORS[detector](prog).detect()) > 0


def _detectors_with_corpus() -> list[str]:
    # A detector corpus dir has a vuln/ and/or safe/ subdir; skip anything else
    # under tests/benchmark/ (e.g. __pycache__ from the Tealer-differential tool).
    return sorted(
        d.name for d in BENCH.iterdir()
        if d.is_dir() and ((d / "vuln").is_dir() or (d / "safe").is_dir())
    )


def run_benchmark() -> dict[str, Score]:
    scores: dict[str, Score] = {}
    for det in _detectors_with_corpus():
        s = Score()
        for case in sorted((BENCH / det / "vuln").glob("*.teal")):
            if _fires(det, case):
                s.tp += 1           # correctly flagged a vulnerable contract
            else:
                s.fn += 1           # MISSED a real vulnerability
        for case in sorted((BENCH / det / "safe").glob("*.teal")):
            if _fires(det, case):
                s.fp += 1           # false alarm on a safe contract
            else:
                s.tn += 1
        scores[det] = s
    return scores


def _table(scores: dict[str, Score]) -> str:
    head = f"{'detector':22} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  {'prec':>5} {'rec':>5} {'F1':>5}"
    lines = [head, "-" * len(head)]
    agg = Score()
    for det, s in scores.items():
        agg = Score(agg.tp + s.tp, agg.fp + s.fp, agg.fn + s.fn, agg.tn + s.tn)
        lines.append(f"{det:22} {s.tp:3} {s.fp:3} {s.fn:3} {s.tn:3}  "
                     f"{s.precision:5.2f} {s.recall:5.2f} {s.f1:5.2f}")
    lines.append("-" * len(head))
    lines.append(f"{'OVERALL':22} {agg.tp:3} {agg.fp:3} {agg.fn:3} {agg.tn:3}  "
                 f"{agg.precision:5.2f} {agg.recall:5.2f} {agg.f1:5.2f}")
    return "\n".join(lines)


# Per-detector confusion baseline (tp, fp, fn, tn). Pins current behaviour so any
# regression (a new FP, a lost TP) fails the test. Update DELIBERATELY when the
# corpus grows or a detector intentionally changes -- and say why.
#
# Representation-sensitive policies use one canonical detector ID. Their corpus
# is the union of the former SSA/IR fixtures, so this ratchet measures the chosen
# implementation rather than scoring two implementations of the same policy.
_BASELINE: dict[str, tuple[int, int, int, int]] = {
    # +1 TN (2026-09-01): match-dispatch on a scratch-round-tripped selector.
    # The predicate layer already resolves the round-trip for match keys, so
    # this pins the safe shape; the detector's own matcher now also resolves
    # through copies defensively (the documented `_value_flow` contract).
    # +2 TN / +1 TP (2026-10-10 review 7/3): TNs = UNMODIFIED `puyapy -O1`
    # ARC4 output with bare create/update handlers and the PyTeal Router bare
    # create — both dispatch bare calls under `NumAppArgs == 0`, where there is
    # no selector to check, yet every compiler-emitted bare handler was flagged
    # (180/231 mainnet probes carried rows). TP = the selector asserted equal
    # to ANOTHER ApplicationArgs entry: enforced, but the caller supplies both
    # sides, so nothing is gated.
    # +2 TN (2026-10-10 precision pass, field-measured): `lifecycle_oc_paths_
    # unpinned` — the create path and OnCompletion != NoOp handlers are not
    # method calls (211 mainnet FP cells, class `lifecycle-oc-path`); `arg0_
    # data_payload_no_router` — a pre-ABI app that never COMPARES arg 0 has no
    # method table (123 cells, `no-method-dispatch`). `selector_unchecked` was
    # rewritten from a bare `arg0; pop` (no router: now out of scope) to a
    # router whose unknown selector falls through to approval.
    "abi-method-selector": (2, 0, 0, 8),
    # +1 TP (2026-07-26): the `||`-bypass. See the rekey-to entry below — the
    # same exploitable hole existed in every detector on this enforcement path.
    # +1 TP # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TP: `AssetCloseTo != Sender` asserted.
    "asset-close-to": (5, 0, 0, 4),
    # +2 TP # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TPs: `XferAsset != 0` asserted; `XferAsset == btoi(arg 0)`.
    "asset-id-validation": (3, 0, 0, 2),
    "box-key": (3, 0, 0, 2),
    # +1 TN (2026-07-25): a HAND-WRITTEN fixture. The corpus is otherwise
    # compiled output, whose shape is narrow and regular — the branch-polarity
    # FP found this session was an idiomatic hand-written guard no compiler
    # emits, so no fixture contained one.
    # +1 TP (2026-07-26): the `||`-bypass — see the rekey-to entry.
    # +1 TP / +1 TN # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TP: compared to `arg 0`; TN: pinned to a fixed owner address.
    "close-remainder-to": (5, 0, 0, 6),
    "constant-condition": (4, 0, 0, 4),
    # +2 TN each (2026-07-25 review, OnCompletion FP-stress): the guard
    # round-tripped through scratch and the guard joined at a phi were both
    # FALSE POSITIVES — the path predicate lands on the `load`/phi, not the
    # comparison, so every OnCompletion detector read the guard as absent.
    # +1 TN (2026-10-10 review 6): a shared `approve:` label reached from two
    # OnCompletion-excluding arms (`OC == NoOp; bnz approve; OC == OptIn; bnz
    # approve; err`). The exit's entry predicates are the INTERSECTION, which is
    # empty, so the action guard read the exit as reachable with Delete — at
    # HIGH, with no creator guard to rescue it. Now a per-EDGE walk.
    # +2 TN / +1 TP (2026-10-10 precision pass, field-measured): TN `delete_
    # drains_first` — an inner CloseRemainderTo on every path to the Delete exit
    # is balance handling (67 mainnet FP cells); TN `gated_delete_app_cannot_
    # move_funds` — no itxn_submit (TEAL 4) + creator-gated delete strands
    # nothing (54 cells). TP `balance_minbalance_different_accounts` — the tie
    # must be balance/min_balance OF THE SAME ACCOUNT (an FN before).
    # +2 TN: `delete_drains_when_nonempty` (the `balance != 0; bz skip`
    # edge proves an empty account) and `drain_after_shared_helper` (a
    # helper's retsub fan-out must not stitch the other method's call site
    # onto the Delete method's post-close continuation: realizable walk).
    "delete-funds-check": (3, 0, 0, 8),
    # +1 TN (2026-07-25): a HAND-WRITTEN fixture. The corpus is otherwise
    # compiled output, whose shape is narrow and regular — the branch-polarity
    # FP found this session was an idiomatic hand-written guard no compiler
    # emits, so no fixture contained one.
    # +1 TP (2026-07-26): the `||`-bypass — see the rekey-to entry.
    # +1 TN (2026-10-10 review 12): `global GroupSize == 1; assert; gtxn 0
    # Fee <= K`. A one-txn group has only position 0, so `gtxn 0` IS the
    # signer's own field; the pin reader knew only `GroupIndex == N`.
    # +1 TP / +1 TN # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TP: `Fee > 0` (lower bound); TN: `1000 >= Fee` (upper bound, reversed).
    "fee-validation": (3, 0, 0, 6),
    # +1 TP / +1 TN (2026-10-10 precision pass): scope is now PER EXIT — an
    # exit is judged only when a realizable path reaches it through an
    # absolute gtxn read (195 mainnet FP cells flagged every exit once ANY gtxn
    # existed). TN = a second method with no sibling read; TP = the read sits
    # in a helper subroutine (the return-stack walk must follow the call).
    # +1 TP / +1 TN # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TP: `GroupSize >= 2` (lower bound); TN: `GroupSize <= 2`.
    # +1 TN (return-stack walk): `groupsize_bound_before_shared_helper` — the
    # shared must-cross walk is REALIZABLE, so a bound asserted before one call
    # of a shared helper is not lost through another caller's retsub edge
    # (24 mainnet FP cells, class `groupsize-bounded-on-path`).
    "group-size-check": (3, 0, 0, 5),
    "hardcoded-min-balance": (1, 0, 0, 1),
    "inner-txn-close-rekey": (1, 0, 0, 1),
    # +1 TP (2026-10-10 review 16): `global MinTxnFee` as the inner fee — a
    # non-zero protocol constant, and PyTeal's `Global.min_txn_fee()` is the
    # commonest spelling of "the app pays"; only an `int` literal was flagged.
    "inner-txn-fee": (2, 0, 0, 1),
    "arbitrary-inner-appcall": (4, 0, 0, 4),
    # +1 TP (2026-08-11): a real-contract shape keeps the attacker-selected
    # asset and fixed treasury receiver in scratch across a subroutine call.
    # The old cross-layer SSA suppression conflated scratch provenance and
    # called this a withdrawal-to-Sender; pre-IR proves it is not.
    # +1 TP / +1 TN (2026-10-10 precision pass): TN = a 0-amount axfer to the
    # app itself with no close — an OPT-IN (24 mainnet FP cells); TP = the same
    # shape plus AssetCloseTo a caller-named account (the holding leaves).
    "arbitrary-inner-asset": (4, 0, 0, 4),
    "tainted-asset-admin": (2, 0, 0, 3),
    "tainted-fee": (1, 0, 0, 2),
    "tainted-freeze": (1, 0, 0, 2),
    # +2 TN (2026-07-25): a sender guard whose RESULT is round-tripped through
    # scratch, and the same joined at a phi — both were FPs until
    # `fund_flow._scratch_value_edges` bridged the IR-level round-trip.
    #
    # +3 TP / +1 TN (2026-07-26 review): comparison SENSE. `_classify` credited
    # any structural appearance of `txn Sender` / `CreatorAddress` in a guard,
    # so all three of `assert(Sender != creator)`, a payout on the FALSE edge of
    # `Sender == creator`, and `assert(Sender == ApplicationArgs[2])` read as
    # sender-guarded — each admits every attacker. The polarity was already
    # computed in `_dominating_guards` and stored on `Guard()`; nothing read it.
    # The new TN pins the shape the fix must NOT break: the same guard spelled as
    # a rejecting inequality (`!=; bnz reject`), which is a real guard.
    #
    # +17 TP / +10 TN (2026-10-10 lift review). Guard credit became COVERAGE
    # of every tainted leaf (was: any tainted register checked by any guard):
    # TPs for `btoi(arg0)+btoi(arg1)` / `phi(arg0, arg1)` with one term
    # bounded, and the interprocedural twin; a comparison against another
    # attacker input (`Accounts[1] == Accounts[2]`, `arg0 <= arg1`); the
    # `gtxnsa` stack txn-index key collision (constant and computed index);
    # non-boolean combinators read as conjunctions (`select` with a constant
    # arm, `| 1`, `+ 1`, `^ 1` around a sender pin); a callee `len` check
    # read as a value check; `Accounts[1] == app_global_get "payee"` with an
    # unguarded writer; `amount > 0` (the `!= 0` exclusion, now consistent);
    # the attacker-LAST Receiver overwrite; the on-path scratch overwrite
    # control; and `dynamic_accounts_index_recipient.teal`, moved here from
    # the partial corpus — the attacker-indexed `txnas Accounts` read is its
    # own uncovered leaf, so the coarse engine now reports it and the partial
    # detector yields ownership by design. TNs are the shapes the fixes must
    # NOT break: `select` with both arms a pin, the SUM bounded, `txn` vs
    # `txna` spellings of one slot, a sanitizer that asserts and RETURNS its
    # param, post-sink `bnz ok; err` and `Sender == creator; return`, the
    # post-call assert in the CALLER, the Receiver overwritten before submit,
    # a scratch round-trip with a dead-end second store, and an input bounded
    # by the group sibling's `gtxn 0 Amount`.
    # +1 TP / +3 TN (2026-10-10 engine, StateValue source): Receiver <-
    # `app_global_get "payee"` whose only writer stores caller input with no
    # sender check (set-then-drain; reported one severity step down). TNs: the
    # writer under `Sender == CreatorAddress`, the writer on the creation call
    # only, and no writer of "payee" at all beside an unguarded writer of a
    # DIFFERENT constant key.
    # +1 TP / +2 TN (2026-10-10 precision pass, authority gaps): TN = a
    # payout under `global CallerApplicationID == <const>` (only that fixed
    # app can call) and under a CREATOR-SIGNED sibling (`gtxn 0 Sender ==
    # CreatorAddress`: the signature covers the group id). TP = `Caller
    # ApplicationID != 0` — any app the attacker deploys passes it.
    "tainted-fund-flow": (32, 0, 0, 27),
    "tainted-log": (2, 0, 0, 3),
    # +1 TN (2026-10-10): `assert(key == "a" || key == "b")` — an `||` that
    # must hold is a JOIN crediting what EVERY arm credits, so a constant-set
    # pin on one key is a guard.
    "tainted-state-write": (2, 0, 0, 4),
    # +3 TP (2026-09-02 review 1.4/1.5): the byte engine's generic fallback
    # tagged bytes-producing ops SCALAR (sha512, `txnas Accounts` at an
    # attacker index) so the taint died at the next slice, and an
    # attacker-chosen offset into a CLEAN table read as clean. All three were
    # silent while the sha256 / direct-txnas controls fired.
    # -1 TP (2026-10-10): `dynamic_accounts_index_recipient.teal` moved to the
    # tainted-fund-flow corpus (see there) — its byte channel is pinned at the
    # engine in `test_review_2026_09_02_analysis.py`.
    "partial-tainted-fund-flow": (6, 0, 0, 5),
    # +2 TN each (2026-07-25 review, OnCompletion FP-stress): the guard
    # round-tripped through scratch and the guard joined at a phi were both
    # FALSE POSITIVES — the path predicate lands on the `load`/phi, not the
    # comparison, so every OnCompletion detector read the guard as absent.
    # +1 TN (2026-10-10 review 6): the shared-approve-label router — see
    # delete-funds-check.
    "is-deletable": (1, 0, 0, 4),
    # +2 TN (2026-07-25): the Update-action half of the OnCompletion
    # scratch/phi guard fix — verified clean, now pinned.
    # +1 TP (2026-09-02): `txn OnCompletion; bnz other` truthiness dispatch —
    # OC != 0 excludes NoOp ONLY, yet a mutant excluding every action survived
    # every gate (tests F1 / M10). The corpus had no truthiness dispatch.
    # +1 TN (2026-10-10 review 6): the shared-approve-label router — see
    # delete-funds-check. +2 TN (review 13): OnCompletion read as `txn
    # GroupIndex; gtxns OnCompletion` (the dynamic-self spelling) and the
    # ordered bound `OC <= OptIn; assert` — neither was an OC guard.
    "is-updatable": (2, 0, 0, 6),
    "lease-validation": (1, 0, 0, 1),
    # +3 TN (2026-07-25 review): the two negated-guard branch polarities and the
    # diamond-joined guard — all three were FALSE POSITIVES before the fix, and
    # the corpus had no safe case covering either shape.
    #
    # +1 TP / +2 TN (2026-07-26 review): the `||`-bypass. The enforcement walk
    # crossed `||` unconditionally, so `assert(RekeyTo == ZeroAddress || Fee <
    # 1000)` read as a rekey guard — an attacker sends a low-fee transaction and
    # takes the account. Exploitable, and it was silent in rekey-to,
    # close-remainder-to, asset-close-to and fee-validation alike. The two new
    # TNs are the shapes the fix must NOT break: a disjunction whose every arm
    # pins the field (a real pin), and the same guard composed with `&&` (which
    # genuinely does force each conjunct).
    # +1 TP (2026-09-01): a self-loop ENTRY (top-level retry loop). The entry
    # walk keyed on "no predecessors" saturated — every exit read protected
    # with an EMPTY gate set — silencing the whole field family on exactly the
    # hostile shape. Entries now come from `prog.entry_blocks()`.
    # +1 TP (2026-10-10 review 1): a RekeyTo validator sub called from TWO
    # arms, one asserting the verdict and one popping it. The callee's `int 0;
    # retsub` was credited as a rejection once ANY caller acted on it, so the
    # popping arm read as guarded. Credit is now per return-target phi.
    # +1 TP # (2026-10-10 precision pass, weak-check FN class): the check must constrain
    # the field to a SAFE value (`_field_protection.SAFE_RULES`), not merely compare it.
    # TP: `RekeyTo != Sender` asserted.
    "rekey-to": (10, 0, 0, 11),
    # +2 TN (2026-07-25): the Update-action half of the OnCompletion
    # scratch/phi guard fix — verified clean, now pinned.
    # +1 TN (2026-10-10 review 11): a ROUND-based delay (`global Round >=
    # stored unlock round`) — only `LatestTimestamp` seeded the timelock.
    "timelock-upgrade": (1, 0, 0, 4),
    # +1 TN (2026-07-25): a HAND-WRITTEN fixture. The corpus is otherwise
    # compiled output, whose shape is narrow and regular — the branch-polarity
    # FP found this session was an idiomatic hand-written guard no compiler
    # emits, so no fixture contained one.
    "tx-type-check": (1, 0, 0, 2),
    # +2 TN each (2026-07-25 review, OnCompletion FP-stress): the guard
    # round-tripped through scratch and the guard joined at a phi were both
    # FALSE POSITIVES — the path predicate lands on the `load`/phi, not the
    # comparison, so every OnCompletion detector read the guard as absent.
    # +1 TN (2026-07-26 review): the creator guard on the ACTION BRANCH,
    # falling through to a shared epilogue. Path predicates at a join are the
    # intersection of the incoming paths, so the guard was invisible there and
    # the contract read "deletable by anyone" — on ~82% of distinct real
    # mainnet contracts, at HIGH. A shared return block is what every
    # optimising compiler emits. Fixed by walking back over EDGES
    # (`sender_creator_guard_covers_action`), which can express "this edge is
    # not an Update path" where a block cannot.
    # +1 TN (2026-07-27, from the expanded probe corpus): only
    # `Sender == global CreatorAddress` counted as authorisation, so the two
    # ways real apps actually gate an upgrade — an admin address held in global
    # state (CreatorAddress is immutable and cannot be rotated) and a hardcoded
    # `addr` literal — both read as "deletable by anyone". A v2 mainnet app in the
    # corpus does exactly this, rejecting with `err` when the sender is not the
    # stored admin. The new TP is the shape that must stay a finding: an "admin"
    # the CALLER supplies, which authorises nothing.
    # +1 TN (2026-07-27): the app-CREATION path. Every router opens
    # `txn ApplicationID; int 0; ==; bnz create`, and the create handler does not
    # inspect OnCompletion — so an accept IS reachable there with OnCompletion ==
    # DeleteApplication. It still cannot be the claimed vulnerability: with
    # ApplicationID == 0 the caller is creating a NEW app, so the action applies
    # to the app being created in that same transaction, which the caller made
    # and already controls. Holds regardless of what the protocol's
    # well-formedness rules permit, so it needed no ruling from a node.
    # +1 TP / +2 TN (2026-09-02): TP = `ApplicationID == 1234` dispatch, which
    # is NOT the creation path (a mutant dropping the `== 0` test survived every
    # gate — tests F1 / M14). TNs = the PuyaPy `txn OnCompletion; switch` router
    # with creator-guarded `proto` Update/Delete handlers (first switch-on-OC
    # fixture in the lifecycle family) and the `bz`-spelled creation dispatch
    # (previously pinned for Update only).
    "unprotected-deletable": (2, 0, 0, 9),
    # +2 TN (2026-07-25): the Update-action half of the OnCompletion
    # scratch/phi guard fix — verified clean, now pinned.
    # +1 TN (2026-07-26 review): the creator guard on the ACTION BRANCH,
    # falling through to a shared epilogue. Path predicates at a join are the
    # intersection of the incoming paths, so the guard was invisible there and
    # the contract read "updatable by anyone" — on ~82% of distinct real
    # mainnet contracts, at HIGH. A shared return block is what every
    # optimising compiler emits. Fixed by walking back over EDGES
    # (`sender_creator_guard_covers_action`), which can express "this edge is
    # not an Update path" where a block cannot.
    # +2 TN / +1 TP (2026-07-27, from the expanded probe corpus): only
    # `Sender == global CreatorAddress` counted as authorisation, so the two
    # ways real apps actually gate an upgrade — an admin address held in global
    # state (CreatorAddress is immutable and cannot be rotated) and a hardcoded
    # `addr` literal — both read as "updatable by anyone". A v2 mainnet app in the
    # corpus does exactly this, rejecting with `err` when the sender is not the
    # stored admin. The new TP is the shape that must stay a finding: an "admin"
    # the CALLER supplies, which authorises nothing.
    # +1 TN (2026-07-27): the app-CREATION path. Every router opens
    # `txn ApplicationID; int 0; ==; bnz create`, and the create handler does not
    # inspect OnCompletion — so an accept IS reachable there with OnCompletion ==
    # UpdateApplication. It still cannot be the claimed vulnerability: with
    # ApplicationID == 0 the caller is creating a NEW app, so the action applies
    # to the app being created in that same transaction, which the caller made
    # and already controls. Holds regardless of what the protocol's
    # well-formedness rules permit, so it needed no ruling from a node.
    # +2 TP / +2 TN (2026-09-01): the entry-detection and guard-spelling
    # cluster. TPs: a single-block always-approve program (the exit IS the
    # entry, so the creator walk fell through to "covered") and a self-loop
    # entry. TNs: the creation dispatch spelled `txn ApplicationID; bz create`
    # (kind "zero" — the commoner spelling, missed by the kind-"eq"-only
    # check, a mainnet-scale FP) and the creator guard spelled `!=; bnz
    # reject` (the surviving path carries equality; same defect class as the
    # fixed disequality-as-input-check).
    # +3 TP / +1 TN (2026-09-02): the three guard-helper mutants that survived
    # every gate (tests F1): an INVERTED creator guard spelled as a branch
    # (`Sender != Creator; bnz upd` — polarity-blind M9, previously caught only
    # by the mainnet ratchet), the `txn OnCompletion; bnz` truthiness dispatch
    # (M10) and `ApplicationID == 1234` read as the creation path (M14). TN =
    # the PuyaPy `txn OnCompletion; switch` router with creator-guarded `proto`
    # handlers — no switch-on-OC fixture existed in any OC-family detector.
    # +1 TP (2026-10-10 review 1): `is_creator` called from the NoOp arm
    # (asserted) AND the Update arm (popped) — the caller-blind callee-verdict
    # credit; see rekey-to.
    # +2 TN (2026-10-10 review 9/10): a PHI of two separately computed
    # `Sender == Creator` pins (PyTeal `If(c, S == C, S == C)` as the `Assert`
    # operand — join = OR, every arm pins) and `assert(Sender == Creator || OC
    # != UpdateApplication)`, whose non-sender leaf EXCLUDES the action under
    # test, so every Update path is creator-checked. +1 TN (review 8): `main:
    # callsub approval_program; return` whose Update arm returns `Sender ==
    # Creator` from its retsub block — the verdict is a PHI of retsub arms,
    # and the pin arm's EDGE into the phi's block is now closed.
    # +1 TP (2026-10-10 engine, guard-walker mutation gate): `assert(Sender ==
    # Creator || btoi(arg0))` — the `||` is a JOIN, so the pin guarantees
    # nothing. The walker's join->union mutation survived on the SSA engine
    # until this fixture: no fixture pinned the sender-pin join there.
    # +2 TP / +3 TN (2026-10-10 precision pass, authority gaps): TNs =
    # creator-signed sibling, `gtxn 0 Sender` under GroupSize==1 &&
    # GroupIndex==0, fixed CallerApplicationID. TPs = `CallerApplicationID ==
    # 0` (no pin) and a sibling sender compared to a caller-supplied address.
    # +1 TP: `gtxn 1 Sender == stored "Escrow"` — a configured LOGICSIG
    # address is not a signing principal (its program signs for anyone).
    "unprotected-updatable": (12, 0, 0, 16),
    "unsafe-division-order": (3, 0, 0, 3),
    # +1 TP (2026-10-10 review 2): the gate spelled `arg 0; byte K; !=; bnz
    # reject` — an equality key by any other op; only `==`/`b==` were sinks.
    "unsafe-lsig-args": (2, 0, 0, 1),
    # 7th vuln case: a validator sub whose 0-return the caller DISCARDS. It
    # lived in safe/ until 2026-07-30, encoding the belief that `int 0;
    # retsub` is a program rejection — it is not. Plus two safe cases where
    # the caller DOES act on the verdict (assert / branch).
    # +2 TP (2026-10-10 review 4/5): a receiver pinned to `app_local_get(Sender,
    # "payee")` that the OPT-IN arm writes from `txna Accounts 1` (the attacker
    # pays themselves and is credited — the op whitelist trusted every state
    # read; writer provenance now comes from the authority layer), and an ARC4
    # `match` router of two `proto` subs where `deposit_impl` pins and
    # `swap_impl` credits unpinned — the per-arm path check was disabled for
    # EVERY program containing a subroutine, i.e. all compiler output; it is
    # now gated on LEGACY (pre-`proto`) subs only. +1 TN: the CONTEXT hazard
    # that gate existed for — a `proto` helper reading the amount, called from
    # one arm that pins BEFORE the call and one that pins AFTER; the forward
    # suffix walk now carries a return stack, so the helper's `retsub` no
    # longer lands in the other arm's continuation.
    # +1 TP / +1 TN (2026-10-10 precision pass): TN = receiver pinned to an
    # "Escrow" whose only writer needs a creator-SIGNED sibling; TP = the twin
    # whose writer pins the sibling's RECEIVER (anyone can satisfy it).
    "unvalidated-group-sibling": (10, 0, 0, 12),
}


def test_benchmark_baseline(capsys):
    scores = run_benchmark()
    with capsys.disabled():
        print("\n" + _table(scores) + "\n")
    actual = {d: (s.tp, s.fp, s.fn, s.tn) for d, s in scores.items()}
    assert actual == _BASELINE, (
        "detector behaviour changed vs the benchmark baseline; review the new "
        "FP/FN and update _BASELINE intentionally"
    )


def test_published_precision_doc_is_current():
    """``docs/PRECISION.md`` is GENERATED but nothing forced regeneration, so it
    silently went stale — it advertised 74+84 ground-truth cases while the
    corpus on disk held 80+98, and carried an out-of-date severity. The
    published numbers are the project's public quality claim; a stale one is
    worse than none."""
    from pathlib import Path

    from gen_precision import OUT, build_report

    assert Path(OUT).read_text() == build_report(), (
        "docs/PRECISION.md is out of date — regenerate with "
        "`python -m tests.gen_precision` and commit it"
    )
