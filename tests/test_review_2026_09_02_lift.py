"""Pins for the 2026-09-02 audit's lift-layer defects. One test per DEFECT, the
control (the repro's safe twin) folded into the same test.

Dominant class this round: a JOIN (phi arms, a callee's `retsub` set) is an OR,
and the fund-flow guard classifier credited it as an AND — any one arm pinning
the sender made `assert(phi(1, Sender == creator))` read as a sender guard.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram

TESTS_DIR = Path(__file__).resolve().parent
_REPRO = TESTS_DIR / "contracts" / "repro"


def _lifter(path):
    from tealql.tealtools.lift.lift import _Lifter
    lifter = _Lifter(SSAProgram(str(path)))
    lifter.build()
    return lifter


def _flows(teal: str, tmp_path, name="prog.teal"):
    from tealql.tealtools.lift.fund_flow import tainted_fund_flows
    p = tmp_path / name
    p.write_text(teal)
    return tainted_fund_flows(_lifter(p))


def _verdict(flows) -> dict:
    """``{field: guarded}`` — every sink must be present (a lost SINK is not a
    clean verdict)."""
    return {f.field: f.guarded for f in flows}


_PAYOUT = (
    "itxn_begin\nint pay\nitxn_field TypeEnum\n"
    "txna ApplicationArgs 0\nitxn_field Receiver\nint 1000\nitxn_field Amount\n"
    "itxn_submit\nint 1\nreturn\ncreate:\nint 1\nreturn\n"
)
_HEAD = "#pragma version 10\ntxn ApplicationID\nbz create\n"


def test_join_is_a_disjunction_every_arm_must_pin(tmp_path):
    """`assert(phi(1, Sender == creator))` is BYPASSABLE on the constant arm
    (findings 1.1) — via a phi, via a two-`retsub` callee, and via PuyaPy's own
    inlining of `if n == 3: return True; return sender == creator`. Controls:
    both arms pinning the sender stays guarded, and a `0` arm is DEAD under an
    assert (that path can never reach the sink) so it does not break the credit."""
    phi_bypass = (_HEAD + "txn NumAppArgs\nint 2\n==\nbnz short\n"
                  "txn Sender\nglobal CreatorAddress\n==\nb join\n"
                  "short:\nint 1\njoin:\nassert\n" + _PAYOUT)
    assert _verdict(_flows(phi_bypass, tmp_path)) == {"Receiver": False}

    multi_return = (_HEAD + "callsub check\nassert\n" + _PAYOUT +
                    "check:\nproto 0 1\ntxn NumAppArgs\nint 2\n==\nbnz skip\n"
                    "txn Sender\nglobal CreatorAddress\n==\nretsub\nskip:\nint 1\nretsub\n")
    assert _verdict(_flows(multi_return, tmp_path)) == {"Receiver": False}

    # puyapy 5.7.1 -O1 output of tests/contracts/repro/or_bypass_puya (is_ok inlined):
    # `pay2` asserts a phi of `intc_0 // 1` and `Sender == CreatorAddress`.
    from tealql.tealtools.lift.fund_flow import tainted_fund_flows
    puya = tainted_fund_flows(_lifter(_REPRO / "or_bypass_puya.approval.teal"))
    assert puya and not any(f.guarded for f in puya), [f.pretty() for f in puya]

    both_pin = (_HEAD + "txn NumAppArgs\nint 2\n==\nbnz short\n"
                "txn Sender\nglobal CreatorAddress\n==\nb join\n"
                "short:\ntxn Sender\nglobal CreatorAddress\n==\njoin:\nassert\n" + _PAYOUT)
    assert _verdict(_flows(both_pin, tmp_path)) == {"Receiver": True}

    dead_zero_arm = (_HEAD + "txn NumAppArgs\nint 2\n==\nbnz short\n"
                     "txn Sender\nglobal CreatorAddress\n==\nb join\n"
                     "short:\nint 0\njoin:\nassert\n" + _PAYOUT)
    assert _verdict(_flows(dead_zero_arm, tmp_path)) == {"Receiver": True}


def test_all_trusted_disjunction_is_a_sender_guard(tmp_path):
    """`assert(Sender == creator || Sender == admin_state)` admits exactly the
    union of two trusted identities — a guard (finding 2.3, the marketplace
    template). Control: one attacker-satisfiable leaf (`|| btoi(arg2)`) keeps
    the refusal — nothing under that `||` is guaranteed."""
    trusted = (_HEAD + "txn Sender\nglobal CreatorAddress\n==\n"
               'txn Sender\nbyte "admin"\napp_global_get\n==\n||\nassert\n' + _PAYOUT)
    assert _verdict(_flows(trusted, tmp_path)) == {"Receiver": True}
    bypass = (_HEAD + "txn Sender\nglobal CreatorAddress\n==\n"
              "txna ApplicationArgs 2\nbtoi\n||\nassert\n" + _PAYOUT)
    assert _verdict(_flows(bypass, tmp_path)) == {"Receiver": False}


def test_sender_read_is_exact_field_not_substring(tmp_path):
    """`txn AssetSender` is a clawback field the attacker sets on their own txn;
    the `"Sender" in imm` substring match credited `assert(AssetSender ==
    creator)` as a sender pin (finding 2.6). Controls: `txna Accounts 0` and
    `int 0; txnas Accounts` ARE the sender; `int 1; txnas Accounts` is not.
    The rule lives in ONE place — `avm.is_current_sender_read` — so the SSA-level
    lifecycle guards and this IR-level classifier cannot drift again."""
    def prog(read):
        return _HEAD + read + "global CreatorAddress\n==\nassert\n" + _PAYOUT

    assert _verdict(_flows(prog("txn AssetSender\n"), tmp_path)) == {"Receiver": False}
    assert _verdict(_flows(prog("txna Accounts 0\n"), tmp_path)) == {"Receiver": True}
    assert _verdict(_flows(prog("int 0\ntxnas Accounts\n"), tmp_path)) == {"Receiver": True}
    assert _verdict(_flows(prog("int 1\ntxnas Accounts\n"), tmp_path)) == {"Receiver": False}

    from tealql.tealtools.ssa.producers import is_current_sender_var
    p = tmp_path / "ssa.teal"
    p.write_text("#pragma version 8\ntxn AssetSender\ntxna Accounts 0\nint 0\ntxnas Accounts\n"
                 "txn Sender\ngtxn 0 Sender\n+\n+\n+\n+\nreturn\n")
    reads = {a.immediates.strip() or a.op: a.outputs[0]
             for bb in SSAProgram(str(p), strict=False).blocks.values()
             for a in bb.assignments if a.op in ("txn", "txna", "txnas", "gtxn")}
    assert not is_current_sender_var(reads["AssetSender"])
    assert not is_current_sender_var(reads["0 Sender"])
    assert all(is_current_sender_var(reads[k]) for k in ("Sender", "Accounts 0", "Accounts"))


def test_caller_sender_guard_reaches_param_less_callee(tmp_path):
    """A `proto 0 0` helper that reads `txna ApplicationArgs` ITSELF has no
    param the caller-guard map could key on, so the owner check dominating its
    only `callsub` was invisible (finding 2.7, the PyTeal `@Subroutine` idiom).
    Every call site pinned (one site; two sites; via an owner-check helper) is
    clean; ONE unpinned site keeps the finding; guard-in-callee and inline
    controls are unchanged."""
    helper = ("send_funds:\nproto 0 0\nitxn_begin\nint pay\nitxn_field TypeEnum\n"
              "txna ApplicationArgs 1\nitxn_field Receiver\ntxna ApplicationArgs 2\n"
              "btoi\nitxn_field Amount\nitxn_submit\nretsub\nok:\nint 1\nreturn\n")
    head = "#pragma version 8\ntxn ApplicationID\nbz ok\n"
    pin = "txn Sender\nglobal CreatorAddress\n==\nassert\n"
    dispatch = 'txna ApplicationArgs 0\nbyte "a"\n==\nbnz method_a\n'

    single_site = head + pin + "callsub send_funds\nint 1\nreturn\n" + helper
    two_sites_pinned = (head + dispatch + pin + "callsub send_funds\nint 1\nreturn\n"
                        "method_a:\n" + pin + "callsub send_funds\nint 1\nreturn\n" + helper)
    via_owner_helper = (head + "callsub check_owner\ncallsub send_funds\nint 1\nreturn\n"
                        "check_owner:\nproto 0 0\n" + pin + "retsub\n" + helper)
    for clean in (single_site, two_sites_pinned, via_owner_helper):
        v = _verdict(_flows(clean, tmp_path))
        assert v == {"Receiver": True, "Amount": True}, v

    one_site_open = (head + dispatch + pin + "callsub send_funds\nint 1\nreturn\n"
                     "method_a:\ncallsub send_funds\nint 1\nreturn\n" + helper)
    assert _verdict(_flows(one_site_open, tmp_path)) == {"Receiver": False, "Amount": False}

    guard_in_callee = (head + "callsub send_funds\nint 1\nreturn\n"
                       + helper.replace("proto 0 0\n", "proto 0 0\n" + pin))
    assert _verdict(_flows(guard_in_callee, tmp_path)) == {"Receiver": True, "Amount": True}
    no_guard = head + "callsub send_funds\nint 1\nreturn\n" + helper
    assert _verdict(_flows(no_guard, tmp_path)) == {"Receiver": False, "Amount": False}


def test_validated_value_ten_hops_upstream_is_still_guarded(tmp_path):
    """`assert(btoi(arg0) <= 1000)` then ten `int 1; +` steps before the sink:
    the def-walk depth cap of 8 cut the guard off and reported UNGUARDED
    (finding 2.8). Sink side and guard side must share ONE bound."""
    from tealql.tealtools.lift import fund_flow
    chain = "int 1\n+\n" * 10
    teal = (_HEAD + "txna ApplicationArgs 0\nbtoi\ndup\nint 1000\n<=\nassert\n" + chain +
            "itxn_begin\nint pay\nitxn_field TypeEnum\nglobal CreatorAddress\n"
            "itxn_field Receiver\nitxn_field Amount\nitxn_submit\nint 1\nreturn\n"
            "create:\nint 1\nreturn\n")
    assert _verdict(_flows(teal, tmp_path)) == {"Amount": True}
    assert fund_flow._WALK_MAX_DEPTH >= 64


def test_applications_index_zero_is_the_current_app_not_attacker_input(tmp_path):
    """`txna Applications 0` is the CURRENT application (go-algorand
    `appIDByIndex`: 0 -> txn.ApplicationID), so paying `app_params_get
    AppCreator` of it is not attacker-steerable — it was labelled
    ForeignApplications and seeded a fund-flow finding (found while classifying
    the ratchet delta of finding 1.1: the OR-bypass had been masking it on two
    mainnet templates). Control: index 1 IS a caller-listed foreign app."""
    from tealql.tealtools.language.avm import attacker_input_label
    assert attacker_input_label("txna", "Applications 0") is None
    assert attacker_input_label("txna", "Applications 1") == "ForeignApplications"
    assert attacker_input_label("txna", "Assets 0") == "ForeignAssets"

    def prog(index):
        return (_HEAD + "itxn_begin\nint pay\nitxn_field TypeEnum\n"
                f"txna Applications {index}\napp_params_get AppCreator\npop\n"
                "itxn_field Receiver\nint 1000\nitxn_field Amount\nitxn_submit\n"
                "int 1\nreturn\ncreate:\nint 1\nreturn\n")
    assert _flows(prog(0), tmp_path) == []
    assert _verdict(_flows(prog(1), tmp_path)) == {"Receiver": False}


@pytest.mark.parametrize("shape", ["no_check"])
def test_depth_cap_control_unchecked_chain_is_flagged(shape, tmp_path):
    """Control for the cap change: the same ten-hop chain WITHOUT the assert is
    still UNGUARDED — a longer walk finds guards, it does not invent them."""
    chain = "int 1\n+\n" * 10
    teal = (_HEAD + "txna ApplicationArgs 0\nbtoi\n" + chain +
            "itxn_begin\nint pay\nitxn_field TypeEnum\nglobal CreatorAddress\n"
            "itxn_field Receiver\nitxn_field Amount\nitxn_submit\nint 1\nreturn\n"
            "create:\nint 1\nreturn\n")
    assert _verdict(_flows(teal, tmp_path)) == {"Amount": False}
