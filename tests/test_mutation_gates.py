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

    def polarity_blind(prog, conds, action_int=None):
        return real(prog, conds, action_int) or any(
            c.kind in ("nonzero", "zero")
            and (G._sender_pin_holds(c.value, prog, True)
                 or G._sender_pin_holds(c.value, prog, False))
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


# The 2026-10-10 review's two highest-priority decisions, each spelled as the
# exact pre-fix behaviour so the gate measures the fixtures that landed with
# the fix — a caller-blind callee-verdict credit and a join-level action guard.


def test_callee_verdict_credited_for_any_caller_is_caught(monkeypatch):
    """Review 1: `_acted_on` crediting the callee's `int 0; retsub` as a
    rejection once ANY return-target phi acts on it. One `callsub check;
    assert` caller then made the callee reject for a second caller that POPS
    the verdict, and the popping arm read as guarded (reached the lifecycle
    AND the field families)."""
    import tealql.security._enforcement as E

    real = E._acted_on

    def any_caller(prog, var, depth=0, truthy=False):
        return real(prog, var, depth, truthy) or any(
            any(a is var for a in ph.args) and real(prog, ph, depth + 1, truthy)
            for ph in prog.phis.values())

    _assert_caught(
        monkeypatch, "tealql.security._enforcement", "_acted_on", any_caller,
        "a callee's returned 0 counts as a rejection once ANY caller acts on it",
    )


def test_action_guard_read_at_the_join_is_caught(monkeypatch):
    """Review 6: `approval_exit_guarded_for_action` reading only the exit's
    entry predicates (the INTERSECTION over incoming paths) instead of walking
    EDGES — a shared `approve:` label reached from two OC-excluding arms then
    read as reachable with Update/Delete."""
    import tealql.security._action_guards as G

    def intersection_only(prog, pp, exit_bb, action_int):
        return G._block_excludes_action(prog, pp, exit_bb, action_int)

    _assert_caught(
        monkeypatch, "tealql.security._action_guards",
        "approval_exit_guarded_for_action", intersection_only,
        "the action guard is decided at the exit's join, not per edge",
    )


# 2026-10-10 precision pass (field-measured): each new scoping / authority /
# safe-value rule, spelled as its pre-fix behaviour, must flip the benchmark.


def _assert_attr_caught(monkeypatch, owner, name, replacement, what: str):
    """`_assert_caught` for a CLASS attribute (a detector method) or a module
    attribute bound only where it is defined."""
    original = getattr(owner, name)
    assert replacement is not original, f"{name}: mutation is a no-op"
    monkeypatch.setattr(owner, name, replacement)
    assert _scores() != _BASELINE, (
        f"MUTATION SURVIVED: {what}. The ground-truth corpus scores identically "
        f"with this broken, so nothing pins that decision.")


def _detector_module(kebab: str):
    import sys

    from tealql.security import DETECTORS
    return sys.modules[DETECTORS[kebab].__module__]


def test_abi_selector_lifecycle_paths_in_scope_is_caught(monkeypatch):
    """`lifecycle_oc_paths_unpinned`: create / OnCompletion != NoOp paths are
    not method calls (211 mainnet FP cells)."""
    cls = _detector_module("abi-method-selector").AbiMethodSelectorDetector
    _assert_attr_caught(monkeypatch, cls, "_lifecycle_path",
                        lambda self, conds: False,
                        "create / non-NoOp OnCompletion paths need a selector")


def test_abi_selector_read_is_routing_is_caught(monkeypatch):
    """`arg0_data_payload_no_router`: reading arg 0 is not routing on it
    (123 mainnet FP cells)."""
    cls = _detector_module("abi-method-selector").AbiMethodSelectorDetector
    _assert_attr_caught(monkeypatch, cls, "_routes_on_selector",
                        lambda self: True,
                        "any program reading ApplicationArgs 0 has a method table")


def test_group_size_program_wide_scope_is_caught(monkeypatch):
    """`gtxn_only_in_other_method`: one gtxn-reading method no longer puts
    every exit in scope (195 mainnet FP cells)."""
    mod = _detector_module("group-size-check")
    _assert_attr_caught(monkeypatch, mod, "exits_after_absolute_group_read",
                        lambda prog, exits, file: {id(e) for e in exits},
                        "every exit is in scope once ANY absolute gtxn exists")


def test_group_size_read_in_helper_missed_is_caught(monkeypatch):
    """`gtxn_in_shared_helper`: the forward walk must follow the call into the
    helper holding the read (a walk that skips callees loses the TP)."""
    mod = _detector_module("group-size-check")

    def caller_only(prog, read_bb, exits, gates=frozenset(), **k):
        return [e for e in exits if e is read_bb]

    _assert_attr_caught(monkeypatch, mod, "exits_reachable_through", caller_only,
                        "an absolute gtxn read reaches only its own block's exit")


def test_groupsize_lower_bound_credited_is_caught(monkeypatch):
    """`groupsize_lower_bound_only` / `fee_lower_bound_only` / `rekey_
    compared_to_sender` …: the safe-value rule. Mutant = any comparison of the
    field is a check (the pre-fix reading)."""
    import tealql.security._field_protection as FP

    def any_comparison(prog, cmp, flows, rule):
        return "truth"

    _assert_attr_caught(monkeypatch, FP, "_safe_field_comparison", any_comparison,
                        "any comparison of the field counts as constraining it")


def test_untrusted_counterpart_credited_is_caught(monkeypatch):
    """`close_compared_to_arg` / `asset_id_vs_arg`: the counterpart must be a
    value no argument can choose."""
    import tealql.security._field_protection as FP
    _assert_attr_caught(monkeypatch, FP, "_trusted_scalar", lambda *a, **k: True,
                        "a caller argument counts as a safe field value")


def test_delete_closeout_not_credited_is_caught(monkeypatch):
    """`delete_drains_first`: an inner CloseRemainderTo on the Delete path is
    balance handling (67 mainnet FP cells)."""
    mod = _detector_module("delete-funds-check")
    _assert_attr_caught(monkeypatch, mod, "_closeout_blocks",
                        lambda prog, file=None: set(),
                        "a close-out inner txn before Delete is not balance handling")


def test_delete_empty_balance_edge_not_credited_is_caught(monkeypatch):
    """`delete_drains_when_nonempty`: the `balance != 0; bz skip` edge."""
    mod = _detector_module("delete-funds-check")
    _assert_attr_caught(monkeypatch, mod, "_proves_app_balance_zero",
                        lambda prog, conds: False,
                        "an edge proving the app balance is zero is not handling")


def test_delete_funds_walk_not_realizable_is_caught(monkeypatch):
    """`drain_after_shared_helper` (and every exit family): the shared
    must-cross walk is REALIZABLE (return stack); the CFG-only backward walk
    stitches another method's call site onto the Delete method's post-close
    continuation."""
    import tealql.security._program_shape as PS

    def cfg_only(prog, exit_bb, *, block_closed, edge_closed=None, within=None):
        return PS._backward_open_ancestors(
            prog, exit_bb, block_closed=block_closed, edge_closed=edge_closed)[0]

    _assert_attr_caught(monkeypatch, PS, "realizable_unguarded_path_exists",
                        cfg_only,
                        "the shared must-cross walk follows unrealizable retsub edges")


def test_delete_app_cannot_move_funds_ignored_is_caught(monkeypatch):
    """`gated_delete_app_cannot_move_funds` (54 mainnet FP cells)."""
    mod = _detector_module("delete-funds-check")
    _assert_attr_caught(monkeypatch, mod, "_app_cannot_move_funds",
                        lambda prog: False,
                        "an app with no inner txns is treated as able to move funds")


def test_delete_balance_accounts_not_tied_is_caught(monkeypatch):
    """`balance_minbalance_different_accounts` (FN): balance and min_balance
    must read the SAME account."""
    mod = _detector_module("delete-funds-check")
    _assert_attr_caught(monkeypatch, mod, "_same_account", lambda *a: True,
                        "balance(app) vs min_balance(Sender) counts as a funds check")


def test_group_signer_not_credited_is_caught(monkeypatch):
    """`creator_signed_sibling` / `gtxn_self_creator_pin` /
    `receiver_pinned_to_creator_signed_escrow`: a fixed group member's sender
    pinned to a signing principal authorises (signatures cover the group id).
    Mutant = the pre-fix rule (current sender only), on BOTH engines."""
    import tealql.security._action_guards as G
    import tealql.tealtools.analysis.authority as AU
    import tealql.tealtools.language.avm as AVM
    import tealql.tealtools.lift.authority as LA
    from tealql.tealtools.ssa.producers import is_current_sender_var
    monkeypatch.setattr(G, "is_group_signer_var", is_current_sender_var)
    monkeypatch.setattr(AU, "is_group_signer_var", is_current_sender_var)
    monkeypatch.setattr(LA, "is_group_signer_read", AVM.is_current_sender_read)
    assert _scores() != _BASELINE, "MUTATION SURVIVED: sibling signers credited"


def test_sibling_signer_vs_any_trusted_address_is_caught(monkeypatch):
    """`receiver_pinned_to_unsigned_sibling_escrow` / the escrow-lsig hazard:
    a sibling signer authorises only against a SIGNING PRINCIPAL, not any
    preserved address (an escrow lsig "signs" by its own logic)."""
    import tealql.security._action_guards as G
    _assert_attr_caught(monkeypatch, G, "_is_signer_principal",
                        lambda prog, var: G._is_trusted_address(prog, var),
                        "a sibling's sender pinned to ANY preserved address authorises")


def test_fixed_caller_app_not_credited_is_caught(monkeypatch):
    """`fixed_caller_application` / `caller_application_pinned`: a pinned
    non-zero CallerApplicationID is an authority, on BOTH engines."""
    import tealql.security._action_guards as G
    import tealql.tealtools.lift.authority as LA
    monkeypatch.setattr(G, "is_fixed_caller_app_pin", lambda x, y: False)
    monkeypatch.setattr(LA, "caller_app_pin", lambda args, d: None)
    assert _scores() != _BASELINE, "MUTATION SURVIVED: caller-app pins credited"


def test_caller_app_zero_credited_is_caught(monkeypatch):
    """`caller_application_zero_is_no_pin` / `caller_application_unpinned`:
    `CallerApplicationID == 0` / `!= 0` pins no app."""
    import tealql.security._action_guards as G
    from tealql.tealtools.ssa import is_field_var

    def any_caller_cmp(x, y):
        return (is_field_var(x, "global", "CallerApplicationID")
                or is_field_var(y, "global", "CallerApplicationID"))

    _assert_attr_caught(monkeypatch, G, "is_fixed_caller_app_pin", any_caller_cmp,
                        "CallerApplicationID compared to anything is a pin")


def test_asset_optin_not_recognised_is_caught(monkeypatch):
    """`optin_self_zero_amount`: a 0-amount axfer to the app itself is an
    opt-in (24 mainnet FP cells)."""
    import tealql.tealtools.lift.fund_flow as FF
    _assert_attr_caught(monkeypatch, FF, "itxn_selector_lines_self_optin",
                        lambda lifter, selector_field="XferAsset": set(),
                        "a self opt-in axfer is an asset outflow")


def test_asset_optin_ignores_close_is_caught(monkeypatch):
    """`optin_shape_with_close_to`: an AssetCloseTo makes it an outflow."""
    import tealql.tealtools.lift.fund_flow as FF
    real_groups = FF._itxn_field_groups

    def no_close(lifter):
        return [{k: v for k, v in g.items() if k != "AssetCloseTo"}
                for g in real_groups(lifter)]

    _assert_attr_caught(monkeypatch, FF, "_itxn_field_groups", no_close,
                        "a close-out on an opt-in-shaped axfer is ignored")
