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
        monkeypatch, "tealql.security.common", "_operand_flows_from_field_var",
        lambda *a, **k: True,
        "the field-flow walk credits EVERY operand",
    )


def test_credit_no_guard_is_caught(monkeypatch):
    """The mirror: nothing ever flows from the field, so every guarded contract
    reads as unguarded. This is the false-POSITIVE direction — the one the
    review actually found three times."""
    _assert_caught(
        monkeypatch, "tealql.security.common", "_operand_flows_from_field_var",
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
    """"Every comparison is enforced" turns dropped checks into real ones."""
    _assert_caught(
        monkeypatch, "tealql.security.common", "def_forward_reaches_enforcement",
        lambda *a, **k: True,
        "every comparison counts as ENFORCED",
    )


def test_never_reaching_enforcement_is_caught(monkeypatch):
    _assert_caught(
        monkeypatch, "tealql.security.common", "def_forward_reaches_enforcement",
        lambda *a, **k: False,
        "no comparison ever counts as enforced",
    )


def test_approval_exit_misclassification_is_caught(monkeypatch):
    """Exit classification decides which paths a detector must protect. Calling
    every block an approving exit — the bug shape found in
    `PathPredicateAnalysis.approving_exits`, where a dead guard let `int 0;
    return` reject arms through — must be caught."""
    _assert_caught(
        monkeypatch, "tealql.security.common", "is_approval_exit",
        lambda bb: bool(getattr(bb, "assignments", None)),
        "every non-empty block counts as an approving exit",
    )


def test_copy_resolution_collapse_is_caught(monkeypatch):
    """`resolve_through_copies` is what makes a guard visible through a scratch
    round-trip or a phi. Making it a no-op restores the exact FP this review
    fixed in the OnCompletion family."""
    _assert_caught(
        monkeypatch, "tealql.security.common", "resolve_through_copies",
        lambda prog, value, *a, **k: value,
        "value-preserving copies are no longer followed",
    )


def test_sender_guard_always_present_is_caught(monkeypatch):
    """A sender/creator guard suppresses findings. Claiming one always
    dominates silences the whole action-guard family."""
    _assert_caught(
        monkeypatch, "tealql.security.common", "sender_creator_guard_dominates",
        lambda *a, **k: True,
        "a sender==creator guard is claimed to dominate everywhere",
    )


def test_the_harness_can_actually_report_a_survivor(monkeypatch):
    """META. Every mutation above is caught — which is the good outcome, but a
    gate that passes unconditionally proves nothing. Feed it a mutation that
    changes NOTHING observable and require it to report survival, so a future
    harness bug (a patch that silently fails to land, as the first version of
    this file did) shows up as a failure here rather than as eight green ticks.
    """
    import tealql.security.common as C

    real = C._operand_flows_from_field_var
    with pytest.raises(AssertionError, match="MUTATION SURVIVED"):
        _assert_caught(
            monkeypatch, "tealql.security.common", "_operand_flows_from_field_var",
            lambda *a, **k: real(*a, **k),          # behaviourally identical
            "a deliberately inert mutation",
        )


def test_unprotected_arg_reads_is_caught(monkeypatch):
    """If arg reads are never credited as protected, a contract that DOES
    assert its selector reads as unchecked — the false-positive direction.

    This mutation SURVIVED until the scratch-round-trip fixture was added. The
    original safe case was covered by the sibling arm ("reached only on a
    matched-selector edge"), so nothing pinned this predicate at all, and the
    whole-suite sweep found it only via the mainnet ratchet — which detects
    CHANGE, not correctness."""
    _assert_caught(
        monkeypatch, "tealql.security.common",
        "approval_exit_protected_for_arg_reads", lambda *a, **k: False,
        "arg reads are NEVER credited as protected",
    )
