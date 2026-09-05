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
_BENCH = TESTS_DIR / "benchmark"


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

    # puyapy 5.7.1 -O1 output (is_ok inlined): `pay2` asserts a phi of
    # `intc_0 // 1` and `Sender == CreatorAddress`.
    from tealql.tealtools.lift.fund_flow import tainted_fund_flows
    puya = tainted_fund_flows(_lifter(
        _BENCH / "tainted-fund-flow" / "vuln" / "puya_inlined_early_return_or_bypass.teal"))
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


def _lifted(teal: str, tmp_path, name):
    from tealql.tealtools.lift.lift import lift
    p = tmp_path / name
    p.write_text(teal)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return prog, lift(prog)


def _main_fails_outright(ir) -> bool:
    from tealql.tealtools.lift import pre_ir
    entry = ir.main.body[0]
    return isinstance(entry.terminator, pre_ir.Fail) and not entry.ops


@pytest.mark.parametrize('backend', [False, True], ids=['core', 'backend'])
def test_straight_line_underflow_from_main_entry_is_a_reject(tmp_path, backend):
    """`cover 3` on one cell, `bury 0`, `int 1; +`: the AVM panics, the lift
    clamped the pops and APPROVED (finding 1.8). Main enters on an empty stack
    — the one exact depth — so the entry is doomed and lowers to `fail`, with
    nothing arity-invalid left for Puya. Controls: a legal `cover 1` approves;
    a proto sub reaching below its own params is LIVE (the caller's residual is
    there) and must stay un-doomed."""
    if backend:
        pytest.importorskip('puya', reason='optional backend lowering')
        from tealql.tealtools.lift.to_puya_ir import render
    else:
        from tealql.tealtools.lift import lift
        def render(prog):
            return lift(prog).render()
    for name, body in {
        "cover": "int 1\ncover 3\nreturn\n",
        "bury0": "int 1\nint 1\nbury 0\nreturn\n",
        "plus": "int 1\n+\nreturn\n",
    }.items():
        prog, ir = _lifted("#pragma version 10\n" + body, tmp_path, f"{name}.teal")
        assert _main_fails_outright(ir), (name, ir.render())
        assert ir.pass_stats["doomed_blocks"] == 1
        lowered = render(prog)
        assert "fail" in lowered and "(+ 1u)" not in lowered, lowered

    prog, ir = _lifted("#pragma version 10\nint 1\nint 2\ncover 1\npop\nreturn\n",
                       tmp_path, "legal.teal")
    assert not _main_fails_outright(ir) and ir.pass_stats["doomed_blocks"] == 0
    assert "exit 2u" in ir.render()

    below = ("#pragma version 10\nint 1\nint 2\nint 3\ncallsub sub\nreturn\nsub:\n"
             "proto 1 1\ntxn NumAppArgs\nbz shallow\nint 7\nb join\nshallow:\njoin:\n"
             "pop\npop\nint 5\nint 6\nint 1\nretsub\n")
    _prog, ir = _lifted(below, tmp_path, "below.teal")
    assert ir.pass_stats["doomed_blocks"] == 0 and ir.pass_stats["doomed_edges"] == 0
    assert "fail" not in ir.render()


@pytest.mark.parametrize('backend', [False, True], ids=['core', 'backend'])
def test_live_cross_family_constant_is_never_coerced(tmp_path, backend):
    """A LIVE constant of the wrong AVM family is an op the AVM rejects; four
    sites still itob/btoi-coerced it and the recompiled program approved with a
    fabricated value (finding 1.9). Every site now goes through ONE helper:
    `int 5` merged with a bytes value -> explicit unknown (never 0x…05); `byte
    "abc"` under `+` -> unknown (never 6382179u); `byte "abc"; bnz` -> `fail`.
    Control: the dead placeholders (`int 0` into a bytes web, `0x` into a uint64
    slot) still coerce silently, as the lift's typed-zero seeds require."""
    if backend:
        pytest.importorskip('puya', reason='optional backend lowering')
        from tealql.tealtools.lift.to_puya_ir import render
    else:
        from tealql.tealtools.lift import lift
        def render(prog):
            return lift(prog).render()
    from tealql.tealtools.lift.type_recovery import cross_family_const
    from tealql.tealtools.lift import pre_ir

    prog, ir = _lifted('#pragma version 10\ntxn NumAppArgs\nbz A\nint 5\nb J\nA:\n'
                       'byte "hello"\nJ:\nlen\nreturn\n', tmp_path, "phi.teal")
    text = ir.render() + render(prog)
    assert "0x0000000000000005" not in text and "undefined" in text, text
    assert ir.pass_stats["cross_family_consts"] == 1

    prog, ir = _lifted('#pragma version 10\nbyte "abc"\nint 1\n+\nreturn\n',
                       tmp_path, "plus.teal")
    text = ir.render() + render(prog)
    assert "6382179" not in text and "undefined" in text, text

    prog, ir = _lifted('#pragma version 10\nbyte "abc"\nbnz yes\nint 0\nreturn\nyes:\n'
                       'int 1\nreturn\n', tmp_path, "bnz.teal")
    assert isinstance(ir.main.body[0].terminator, pre_ir.Fail), ir.render()
    assert "6382179" not in render(prog)

    stats: dict = {}
    assert cross_family_const(pre_ir.UInt64Constant(0), "bytes", stats=stats) == \
        pre_ir.BytesConstant("0x")
    assert cross_family_const(pre_ir.BytesConstant("0x"), "uint64", stats=stats) == \
        pre_ir.UInt64Constant(0)
    assert cross_family_const(pre_ir.UInt64Constant(7), "uint64", stats=stats) == \
        pre_ir.UInt64Constant(7)
    assert stats == {}
    assert cross_family_const(pre_ir.UInt64Constant(7), "bytes", stats=stats) == \
        pre_ir.Undefined(ir_type="bytes")
    assert stats == {"cross_family_consts": 1}


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
