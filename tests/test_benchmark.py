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
# tainted-fund-flow now scores recall 1.0: param_fed_callee.teal (the proto-frame
# param flow the SSA def-use can't see) is rescued by the IR lift's
# interprocedural fund-flow, wired into the detector as a callsub-gated supplement.
_BASELINE: dict[str, tuple[int, int, int, int]] = {
    "abi-method-selector": (1, 0, 0, 1),
    "arbitrary-inner-appcall": (4, 0, 0, 4),
    "arbitrary-inner-asset": (2, 0, 0, 3),
    # +1 TP (2026-07-26): the `||`-bypass. See the rekey-to entry below — the
    # same exploitable hole existed in every detector on this enforcement path.
    "asset-close-to": (4, 0, 0, 4),
    "asset-id-validation": (1, 0, 0, 2),
    "box-key": (3, 0, 0, 2),
    # +1 TN (2026-07-25): a HAND-WRITTEN fixture. The corpus is otherwise
    # compiled output, whose shape is narrow and regular — the branch-polarity
    # FP found this session was an idiomatic hand-written guard no compiler
    # emits, so no fixture contained one.
    # +1 TP (2026-07-26): the `||`-bypass — see the rekey-to entry.
    "close-remainder-to": (4, 0, 0, 5),
    "constant-condition": (4, 0, 0, 4),
    # +2 TN each (2026-07-25 review, OnCompletion FP-stress): the guard
    # round-tripped through scratch and the guard joined at a phi were both
    # FALSE POSITIVES — the path predicate lands on the `load`/phi, not the
    # comparison, so every OnCompletion detector read the guard as absent.
    "delete-funds-check": (2, 0, 0, 3),
    # +1 TN (2026-07-25): a HAND-WRITTEN fixture. The corpus is otherwise
    # compiled output, whose shape is narrow and regular — the branch-polarity
    # FP found this session was an idiomatic hand-written guard no compiler
    # emits, so no fixture contained one.
    # +1 TP (2026-07-26): the `||`-bypass — see the rekey-to entry.
    "fee-validation": (2, 0, 0, 3),
    "group-size-check": (1, 0, 0, 2),
    "hardcoded-min-balance": (1, 0, 0, 1),
    "inner-txn-close-rekey": (1, 0, 0, 1),
    "inner-txn-fee": (1, 0, 0, 1),
    "ir-arbitrary-inner-appcall": (4, 0, 0, 4),
    "ir-arbitrary-inner-asset": (2, 0, 0, 3),
    "ir-tainted-asset-admin": (2, 0, 0, 3),
    "ir-tainted-fee": (1, 0, 0, 2),
    "ir-tainted-freeze": (1, 0, 0, 2),
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
    "ir-tainted-fund-flow": (8, 0, 0, 9),
    "ir-tainted-log": (2, 0, 0, 3),
    "ir-tainted-state-write": (2, 0, 0, 3),
    "ir-partial-tainted-fund-flow": (4, 0, 0, 4),
    # +2 TN each (2026-07-25 review, OnCompletion FP-stress): the guard
    # round-tripped through scratch and the guard joined at a phi were both
    # FALSE POSITIVES — the path predicate lands on the `load`/phi, not the
    # comparison, so every OnCompletion detector read the guard as absent.
    "is-deletable": (1, 0, 0, 3),
    # +2 TN (2026-07-25): the Update-action half of the OnCompletion
    # scratch/phi guard fix — verified clean, now pinned.
    "is-updatable": (1, 0, 0, 3),
    "lease-validation": (1, 0, 0, 1),
    "partial-tainted-fund-flow": (3, 0, 0, 4),
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
    "rekey-to": (6, 0, 0, 10),
    "tainted-fund-flow": (4, 0, 0, 4),
    # +2 TN (2026-07-25): the Update-action half of the OnCompletion
    # scratch/phi guard fix — verified clean, now pinned.
    "timelock-upgrade": (1, 0, 0, 3),
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
    "unprotected-deletable": (1, 0, 0, 6),
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
    "unprotected-updatable": (2, 0, 0, 7),
    "unsafe-division-order": (3, 0, 0, 3),
    "unsafe-lsig-args": (1, 0, 0, 1),
    # 7th vuln case: a validator sub whose 0-return the caller DISCARDS. It
    # lived in safe/ until 2026-07-30, encoding the belief that `int 0;
    # retsub` is a program rejection — it is not. Plus two safe cases where
    # the caller DOES act on the verdict (assert / branch).
    "unvalidated-group-sibling": (7, 0, 0, 10),
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
