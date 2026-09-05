"""Mutation gate: would the suite NOTICE if the guard logic broke?

Every other test asks "is the code right today". This asks the question one
level up — "are the gates load-bearing" — by deliberately breaking the analysis
and requiring the ground-truth benchmark to go red.

That question is not academic here. Throughout the 2026-07-25 review the
benchmark scored a perfect 1.00 while three separate false-positive bugs
shipped, because no fixture exercised the shape that broke. A gate nobody has
tried to defeat is a gate nobody knows the strength of.

Rather than a whole-codebase `mutmut` sweep (hours, and mostly syntactic noise
on a 39k-line project), this mutates the SPECIFIC predicates the detectors'
verdicts hinge on — the guard-recognition road this review found three
independent bugs in — and requires each mutation to be caught. Each runs the
ground-truth benchmark in-process, so the whole file is seconds.

A mutation that is NOT caught is the useful output: it names a decision the
corpus does not currently pin, which is exactly where the next FP or FN will
come from.
"""
from __future__ import annotations

import pytest

from test_benchmark import _BASELINE, run_benchmark


def _scores() -> dict:
    return {d: (s.tp, s.fp, s.fn, s.tn) for d, s in run_benchmark().items()}


def _assert_caught(monkeypatch, target_module, name, replacement, what: str):
    """Apply one mutation and require the benchmark to notice.

    The mutation must be applied to EVERY module that holds the name, not just
    the defining one: `from x import y` binds a local reference, so patching a
    single module leaves the real call sites running the original. Each of
    these functions is bound in two to four modules, and the first version of
    this file patched one — reporting five "surviving mutations" that were
    purely my own harness failing to take effect. A mutation gate that does not
    verify its own mutation lands measures nothing at all."""
    import sys

    holders = [m for m in list(sys.modules.values())
               if getattr(m, "__name__", "").startswith("tealql")
               and getattr(m, name, None) is not None]
    assert holders, f"{name} is bound in no loaded tealql module"
    original = getattr(holders[0], name)
    for mod in holders:
        monkeypatch.setattr(mod, name, replacement)
    # The mutation must actually differ from what it replaced, or "survived"
    # would just mean "identical function".
    assert replacement is not original, f"{name}: mutation is a no-op"
    mutated = _scores()
    assert mutated != _BASELINE, (
        f"MUTATION SURVIVED: {what}. The ground-truth corpus scores identically "
        f"with this broken, so nothing pins that decision — the next false "
        f"positive or negative in it ships silently."
    )


def test_credit_every_guard_is_caught(monkeypatch):
    """If the MUST-flow walk credits every operand as flowing from the field,
    every unguarded contract reads as guarded — the classic false-negative
    direction, and the one that hides real vulnerabilities."""
    _assert_caught(
        monkeypatch, "tealql.security._value_flow", "_operand_flows_from_field_var",
        lambda *a, **k: True,
        "the field-flow walk credits EVERY operand",
    )


def test_credit_no_guard_is_caught(monkeypatch):
    """The mirror: nothing ever flows from the field, so every guarded contract
    reads as unguarded. This is the false-POSITIVE direction — the one the
    review actually found three times."""
    _assert_caught(
        monkeypatch, "tealql.security._value_flow", "_operand_flows_from_field_var",
        lambda *a, **k: False,
        "the field-flow walk credits NOTHING",
    )


def test_branch_polarity_inversion_is_caught(monkeypatch):
    """`branch_gates_rejection` decides whether a `bnz`/`bz` enforces its
    condition. Inverting it is precisely the defect class the review found."""
    import tealql.security._enforcement as E

    real = E.branch_gates_rejection
    _assert_caught(
        monkeypatch, "tealql.security._enforcement", "branch_gates_rejection",
        lambda *a, **k: not real(*a, **k),
        "branch-to-rejection polarity is inverted",
    )


def test_always_reaching_enforcement_is_caught(monkeypatch):
    """"Every comparison is enforced" turns dropped checks into real ones.

    Targets the COLLECTING walk `_collect_field_enforcement_bbs`: since the
    2026-09-02 per-exit conversion of timelock-upgrade / delete-funds-check it is
    the one enforcement engine every benchmarked detector runs; the boolean twin
    `def_forward_reaches_enforcement` has no detector caller left (only
    `test_field_enforcement_soundness` uses it as an oracle), so mutating IT
    measured nothing — both gates here reported "survived" against a dead
    function until retargeted."""
    def every_block(prog, var, label_lines, out, seen, *a, **k):
        out.update(prog.blocks.values())

    _assert_caught(
        monkeypatch, "tealql.security._field_protection", "_collect_field_enforcement_bbs",
        every_block, "every block counts as ENFORCING every comparison",
    )


def test_never_reaching_enforcement_is_caught(monkeypatch):
    _assert_caught(
        monkeypatch, "tealql.security._field_protection", "_collect_field_enforcement_bbs",
        lambda *a, **k: None,
        "no comparison ever counts as enforced",
    )


def test_approval_exit_misclassification_is_caught(monkeypatch):
    """Exit classification decides which paths a detector must protect. Calling
    every block an approving exit — the bug shape found in
    `PathPredicateAnalysis.approving_exits`, where a dead guard let `int 0;
    return` reject arms through — must be caught."""
    _assert_caught(
        monkeypatch, "tealql.tealtools.cfg.exits", "is_approval_exit",
        lambda bb: bool(getattr(bb, "assignments", None)),
        "every non-empty block counts as an approving exit",
    )


def test_copy_resolution_collapse_is_caught(monkeypatch):
    """All consumers now share fact aliases, including predicates themselves.
    Mutate the common identity relation so a surviving compatibility wrapper
    cannot mask the lost scratch/phi semantics."""
    from tealql.tealtools.analysis.context import ValueFacts
    monkeypatch.setattr(ValueFacts, 'resolve', lambda self, value: value)
    assert _scores() != _BASELINE, 'benchmark did not detect lost value identities'


def test_sender_guard_always_present_is_caught(monkeypatch):
    """A sender/creator guard suppresses findings. Claiming one always
    dominates silences the whole action-guard family."""
    _assert_caught(
        monkeypatch, "tealql.security._action_guards", "sender_creator_guard_dominates",
        lambda *a, **k: True,
        "a sender==creator guard is claimed to dominate everywhere",
    )


# The three 2026-09-02 survivors (tests F1: M9, M10, M14). Each is an
# "accept MORE" mutation of one guard decision, spelled as `real(...) or
# <the dropped test>`, so it is exactly the defect the hand-applied diff made
# — and each was 71/71 green against the corpus before its fixture landed.


def test_sender_guard_polarity_blindness_is_caught(monkeypatch):
    """M9: `sender_creator_guard_dominates` (now `_preds_prove_sender_guard`)
    accepting `==`/`!=` under EITHER truth value credits `Sender != Creator;
    bnz upd` — the creator is rejected and everyone else updates. Only the
    mainnet ratchet caught this; the corpus had no branch-spelled inversion."""
    import tealql.security._action_guards as G

    real = G._preds_prove_sender_guard

    def polarity_blind(prog, conds):
        return real(prog, conds) or any(
            c.kind in ("nonzero", "zero")
            and G._trusted_sender_pin_op(c.value, prog) in ("==", "!=")
            for c in conds)

    _assert_caught(
        monkeypatch, "tealql.security._action_guards", "_preds_prove_sender_guard",
        polarity_blind, "a sender pin counts as a guard under EITHER polarity",
    )


def test_oc_nonzero_excluding_every_action_is_caught(monkeypatch):
    """M10: Case 0 of `predicates_exclude_action` without `and action_int == 0`
    reads `OC != 0` as excluding Update/Delete — a `txn OnCompletion; bnz other`
    truthiness dispatch then approves every lifecycle action unguarded."""
    import tealql.security._action_guards as G
    from tealql.security._value_flow import resolve_through_copies

    real = G.predicates_exclude_action

    def nonzero_excludes_all(prog, conds, action_int):
        return real(prog, conds, action_int) or any(
            c.kind == "nonzero"
            and G._is_oncompletion_var(resolve_through_copies(prog, c.value))
            for c in conds)

    _assert_caught(
        monkeypatch, "tealql.security._action_guards", "predicates_exclude_action",
        nonzero_excludes_all, "`OC != 0` is read as excluding every action",
    )


def test_creation_path_for_any_appid_constant_is_caught(monkeypatch):
    """M14: `_is_app_creation_path` without the `== 0` test treats
    `ApplicationID == 1234; bnz matched` as the creation path, whose approvals
    are (rightly) exempt — so the deployed app's unguarded arm reads safe."""
    import tealql.security._action_guards as G
    from tealql.security._value_flow import resolve_through_copies

    real = G._is_app_creation_path

    def any_const_is_creation(prog, conds):
        return real(prog, conds) or any(
            c.kind == "eq" and c.args
            and G._is_txn_field_var(resolve_through_copies(prog, c.value), "ApplicationID")
            for c in conds)

    _assert_caught(
        monkeypatch, "tealql.security._action_guards", "_is_app_creation_path",
        any_const_is_creation, "`ApplicationID == <any const>` counts as creation",
    )


def test_unprotected_arg_reads_is_caught(monkeypatch):
    """The dynamic-expected-value fixture must depend on the enforcement arm,
    not only the separate constant-router path-predicate shortcut."""
    _assert_caught(
        monkeypatch, "tealql.security._field_protection",
        "approval_exit_protected_for_arg_reads", lambda *a, **k: False,
        "enforced argument reads are never credited as protected",
    )


def test_the_harness_can_actually_report_a_survivor(monkeypatch):
    """META. Every mutation above is caught — which is the good outcome, but a
    gate that passes unconditionally proves nothing. Feed it a mutation that
    changes NOTHING observable and require it to report survival, so a future
    harness bug (a patch that silently fails to land, as the first version of
    this file did) shows up as a failure here rather than as eight green ticks.
    """
    import tealql.security._value_flow as C

    real = C._operand_flows_from_field_var
    with pytest.raises(AssertionError, match="MUTATION SURVIVED"):
        _assert_caught(
            monkeypatch, "tealql.security._value_flow", "_operand_flows_from_field_var",
            lambda *a, **k: real(*a, **k),          # behaviourally identical
            "a deliberately inert mutation",
        )


def test_gtxns_any_index_as_signed_txn_is_caught(monkeypatch):
    """M11 (findings.md 1.7): `_signed_txn_field_reads` credits a `gtxns FIELD`
    read only when its index resolves to `txn GroupIndex` ("this"). Dropping
    that test lets a delegated lsig that checks RekeyTo at an ATTACKER-CHOSEN
    sibling index read as guarded — the signer is rekeyable. The mutant appends
    every gtxns/gtxnsa/gtxnsas read of the field, exactly what the slot test
    excludes."""
    import tealql.security._field_protection as FP

    real = FP._signed_txn_field_reads

    def any_index_is_self(prog, field, *, file=None):
        reads = list(real(prog, field, file=file))
        seen = {id(a) for a in reads}
        for a in FP.gtxn_field_reads(prog, field, file=file):
            if a.op in ("gtxns", "gtxnsa", "gtxnsas") and id(a) not in seen:
                reads.append(a)
        return reads

    _assert_caught(
        monkeypatch, "tealql.security._field_protection", "_signed_txn_field_reads",
        any_index_is_self,
        "a gtxns read at ANY group index counts as the signed txn's own field",
    )
