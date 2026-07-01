"""IR-layer attacker-controlled fund-flow detector (``lift.fund_flow``).

Flags user-input-tainted values reaching fund-flow inner-txn fields and gates each
on the dominating guards (asserts / forced branches) that check the SAME value (by
shared register or same input slot) or the transaction Sender.
"""
from pathlib import Path

import pytest

from tealtools.ssa import SSAProgram
from tealtools.lift.lift import _Lifter
from tealtools.lift.fund_flow import tainted_fund_flows

TESTS_DIR = Path(__file__).resolve().parent


def _flows(teal: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    lifter = _Lifter(SSAProgram(str(p), verbose=False))
    lifter.build()
    return tainted_fund_flows(lifter)


_UNGUARDED = """#pragma version 10
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""

_SENDER = """#pragma version 10
    txn Sender
    global CreatorAddress
    ==
    assert
    itxn_begin
    txn ApplicationArgs 0
    btoi
    itxn_field Amount
    itxn_submit
    int 1
    return
"""

_INPUTCHECK = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    dup
    int 100
    <=
    assert
    itxn_begin
    itxn_field Amount
    itxn_submit
    int 1
    return
"""

# The attacker value is read twice -- once for the `> 5` check, once for Receiver.
# Slot-level matching must still recognize the guard.
_BRANCH = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    int 5
    >
    bz reject
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    itxn_submit
    int 1
    return
reject:
    int 0
    return
"""


def test_unguarded_fund_flow(tmp_path):
    flows = _flows(_UNGUARDED, tmp_path)
    rec = [f for f in flows if f.field == "Receiver"]
    assert len(rec) == 1
    f = rec[0]
    assert f.severity == "HIGH"
    assert "ApplicationArgs" in f.sources
    assert not f.guarded and not f.param_derived, "must be flagged UNGUARDED"


def test_sender_guarded(tmp_path):
    flows = _flows(_SENDER, tmp_path)
    amt = [f for f in flows if f.field == "Amount"]
    assert len(amt) == 1
    assert amt[0].guarded
    assert any(g.checks_sender for g in amt[0].guards), "the txn Sender check guards it"


def test_input_value_guarded(tmp_path):
    flows = _flows(_INPUTCHECK, tmp_path)
    amt = [f for f in flows if f.field == "Amount"]
    assert len(amt) == 1
    assert amt[0].guarded
    assert any(g.checks_input for g in amt[0].guards), "the amount<=100 assert guards it"


def test_branch_guard_same_input_slot(tmp_path):
    # The check and the use each read ApplicationArgs[0] separately (distinct
    # registers); slot-level matching must still recognize the branch guard.
    flows = _flows(_BRANCH, tmp_path)
    rec = [f for f in flows if f.field == "Receiver"]
    assert len(rec) == 1
    assert rec[0].guarded, "the bz on arg0>5 forces the path; same slot used"
    assert any(g.checks_input and g.kind == "branch" for g in rec[0].guards)


# The value is checked in the CALLER, then passed into the callee that does the
# itxn -- intra-procedural dominance can't see the guard; interprocedural must.
_CALLER_GUARDED = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    dup
    int 100
    <=
    assert
    callsub pay
    int 1
    return
pay:
    proto 1 0
    itxn_begin
    frame_dig -1
    itxn_field Amount
    itxn_submit
    retsub
"""

# Same shape but the caller does NOT check the value: genuinely unguarded, and the
# detector must say so (not hide behind "param-derived").
_CALLER_UNGUARDED = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    callsub pay
    int 1
    return
pay:
    proto 1 0
    itxn_begin
    frame_dig -1
    itxn_field Amount
    itxn_submit
    retsub
"""


def test_interprocedural_caller_guard_resolves_param(tmp_path):
    flows = _flows(_CALLER_GUARDED, tmp_path)
    amt = [f for f in flows if f.field == "Amount"]
    assert len(amt) == 1
    f = amt[0]
    assert f.guarded, "the caller's amount<=100 check must count"
    assert not f.param_derived, "interprocedural guard resolves the param"
    assert any(g.kind == "caller" and g.checks_input for g in f.guards)


def test_interprocedural_unguarded_is_not_param_derived(tmp_path):
    flows = _flows(_CALLER_UNGUARDED, tmp_path)
    amt = [f for f in flows if f.field == "Amount"]
    assert len(amt) == 1
    f = amt[0]
    assert not f.guarded, "no caller check exists"
    assert not f.param_derived, "the sub IS called, so we resolved it: genuinely unguarded"


def test_no_false_flag_on_untainted_constant(tmp_path):
    # A constant Receiver (not user input) must NOT be flagged at all.
    teal = ("#pragma version 10\n"
            "    itxn_begin\n"
            "    global CurrentApplicationAddress\n"
            "    itxn_field Receiver\n"
            "    int 1\n    itxn_field Amount\n    itxn_submit\n"
            "    int 1\n    return\n")
    assert _flows(teal, tmp_path) == []


def test_robust_on_real_probes():
    """The detector runs without error across a sample of real mainnet probes."""
    probes = sorted((TESTS_DIR / "mainnet-random-probes").glob("app_*.teal"))[:12]
    if not probes:
        pytest.skip("no probe corpus present")
    for p in probes:
        lifter = _Lifter(SSAProgram(str(p), verbose=False))
        lifter.build()
        flows = tainted_fund_flows(lifter)
        for f in flows:                       # well-formed findings
            assert f.field
            assert f.severity in ("CRITICAL", "HIGH", "MEDIUM")
            assert isinstance(f.to_dict(), dict)


def test_ir_taint_chain_crosses_callsub_in_ir_ops():
    # the taint road for a sink fed through a callsub: IR ops, source-first,
    # crossing the call boundary natively (no frame_dig hop like the SSA chain).
    from tealtools.dataflow.byte_taint import byte_taint_view
    from tealtools.lift import fund_flow as FF, pre_ir
    from tealtools.lift.taint import _intr
    teal = ("#pragma version 8\n"
            "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\ncallsub emit\nint 1\nreturn\n"
            "emit:\nproto 1 0\nframe_dig -1\nextract 8 32\nlog\nretsub\n")
    p = SSAProgram.from_text(teal, name="t")
    lf = _Lifter(p); lf.build()
    view = byte_taint_view(lf)
    reg = [s.args[0] for b in pre_ir.blocks(lf.subs) for o in b.ops
           if (s := _intr(o)) and s.op == "log"][0]
    chain = [FF._ir_op_str(o) for o in FF.ir_taint_chain(lf, reg, view)]
    ops = [c.split()[0] for c in chain]
    assert ops[0] == "txna" and "concat" in ops and ops[-1] == "extract"   # source -> sink
    assert "frame_dig" not in ops                                          # IR abstracts the param hop


def test_finding_message_carries_ir_taint_road(tmp_path):
    # a flagged fund-flow finding includes the lifted-IR taint road as a witness.
    # Needs a file-backed prog so common.ir_lifter (source_path) takes the IR path.
    from security import DETECTORS
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\nitxn_begin\nint pay\nitxn_field TypeEnum\n"
            "itxn_field Amount\nitxn_submit\nint 1\nreturn\n")
    f = tmp_path / "prog.teal"
    f.write_text(teal)
    p = SSAProgram(str(f), verbose=False)
    vs = DETECTORS["ir-tainted-fund-flow"](p).detect()
    assert vs, "expected an unguarded tainted Amount finding"
    assert "via:" in vs[0].message and "ApplicationArgs" in vs[0].message
    assert "→" in vs[0].message                    # a road with >=1 hop
