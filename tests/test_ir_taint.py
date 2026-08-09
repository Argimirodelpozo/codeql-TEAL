"""IR-layer user-input taint (``lift.taint``).

Focus: the interprocedural ``_return_summary`` that replaced the old
"call result <- any tainted arg" rule. That rule was simultaneously

  * IMPRECISE -- it tainted a call's result whenever *any* arg was tainted,
    even an arg that never flows to the return; and
  * UNSOUND -- it ignored the callee's return values entirely, so a value the
    callee derives from an INTERNAL source (e.g. it reads ApplicationArgs and
    returns it) reached the caller's result UNtainted -> a missed flow.

The summary fixes both: a result is tainted by the callee's internal-source
returns plus only the params that actually flow through.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift import pre_ir
from tealql.tealtools.lift.lift import _Lifter
from tealql.tealtools.lift.fund_flow import tainted_fund_flows
from tealql.tealtools.lift.summaries import compute_summaries
from tealql.tealtools.lift.taint import (
    UNKNOWN_SOURCE,
    _return_summary,
    _scratch_unknown_write,
    taint_report,
    tainted_sinks,
    user_input_taint,
)

TESTS_DIR = Path(__file__).resolve().parent


def test_dynamic_store_fallback_taints_the_top_first_value_not_the_slot():
    value = pre_ir.Register("value", 0, "uint64")
    slot = pre_ir.Register("slot", 0, "uint64")
    stores = pre_ir.Intrinsic("stores", [], [value, slot], line=1)

    def tainting(target):
        return {UNKNOWN_SOURCE} if target is value else set()

    def selector_only(target):
        return {UNKNOWN_SOURCE} if target is slot else set()

    assert _scratch_unknown_write(stores, tainting) == (None, True)
    assert _scratch_unknown_write(stores, selector_only) == (None, False)


def _lifter(teal: str, tmp_path: Path) -> _Lifter:
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    lifter = _Lifter(prog)
    lifter.build()
    return lifter


def _amount_taint(lifter) -> list:
    """Taint sets of every ``itxn_field Amount`` value operand."""
    t = user_input_taint(lifter)
    out = []
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            s = o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else (
                o.source if isinstance(o, pre_ir.Assignment)
                and isinstance(getattr(o, "source", None), pre_ir.Intrinsic) else None)
            if s is not None and s.op == "itxn_field" and s.immediates \
                    and "Amount" in str(s.immediates[0]):
                for a in s.args:
                    if isinstance(a, pre_ir.Register):
                        out.append(t.get(id(a), frozenset()))
    return out


# A sub that returns ONLY its 2nd (clean) param, ignoring the tainted 1st.
_OVER = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    int 7
    callsub passthru_second
    itxn_begin
    itxn_field Amount
    int 1
    return
passthru_second:
    proto 2 1
    frame_dig -1
    retsub
"""

# A no-arg sub that reads ApplicationArgs internally and returns it.
_UNDER = """#pragma version 10
    callsub reads_arg_internally
    itxn_begin
    itxn_field Amount
    int 1
    return
reads_arg_internally:
    proto 0 1
    txn ApplicationArgs 1
    btoi
    retsub
"""


def test_summary_passthrough_only_flowing_param(tmp_path):
    lifter = _lifter(_OVER, tmp_path)
    summary = _return_summary(lifter)
    srcs, params = summary["passthru_second"]
    assert params == frozenset({1}), "only the returned 2nd param is passthrough"
    assert srcs == frozenset(), "no internal source reaches the return"


def test_no_overtaint_through_nonflowing_arg(tmp_path):
    # The result comes from the CLEAN 2nd arg; the tainted 1st arg does not flow
    # through, so the itxn Amount must NOT be tainted (the old rule tainted it).
    lifter = _lifter(_OVER, tmp_path)
    hits = _amount_taint(lifter)
    assert hits, "expected an itxn_field Amount operand"
    assert all(h == frozenset() for h in hits), f"over-tainted: {hits}"


def test_summary_internal_source_return(tmp_path):
    lifter = _lifter(_UNDER, tmp_path)
    summary = _return_summary(lifter)
    srcs, params = summary["reads_arg_internally"]
    assert "ApplicationArgs" in srcs, "internal source must reach the return"
    assert params == frozenset(), "the sub takes no params"


def test_no_undertaint_of_internal_source_return(tmp_path):
    # The callee derives its return from ApplicationArgs with no args; the old
    # rule (result <- args only) MISSED this flow. The summary must surface it.
    lifter = _lifter(_UNDER, tmp_path)
    hits = _amount_taint(lifter)
    assert hits, "expected an itxn_field Amount operand"
    assert any("ApplicationArgs" in h for h in hits), f"under-tainted (missed flow): {hits}"


def test_summary_wellformed_on_real_contract():
    """On a real multi-subroutine contract the summary is self-consistent: every
    passthrough index is a valid param position, and it runs without error."""
    teals = sorted((TESTS_DIR / "contracts" / "xgov").rglob("*.teal"))
    if not teals:
        pytest.skip("xgov fixture not present (gitignored real contract)")
    prog = SSAProgram(str(teals[0]))
    prog.propagate_constants()
    lifter = _Lifter(prog)
    lifter.build()
    summary = _return_summary(lifter)
    by_id = {s.id: s for s in lifter.subs if not s.is_main}
    for sid, (srcs, params) in summary.items():
        assert sid in by_id
        nparams = len(by_id[sid].parameters)
        assert all(0 <= i < nparams for i in params), f"{sid}: bad passthrough idx"
    # taint still completes end to end
    assert isinstance(user_input_taint(lifter), dict)


def _unknown_lifter():
    """Minimal lifted program: Undefined -> return -> call -> add -> Amount."""
    unknown_value = pre_ir.Register("unknown", 0, "uint64")
    call_result = pre_ir.Register("call", 0, "uint64")
    derived = pre_ir.Register("derived", 0, "uint64")
    loaded = pre_ir.Register("loaded", 0, "uint64")
    unknown_sub = pre_ir.Subroutine(
        "unknown_sub", [], ["uint64"], [pre_ir.BasicBlock(
            10, [], [pre_ir.Assignment(
                [unknown_value], pre_ir.Undefined(ir_type="uint64"))],
            pre_ir.SubroutineReturn([unknown_value]))])
    main = pre_ir.Subroutine(
        "main", [], [], [pre_ir.BasicBlock(
            0,
            [],
            [
                pre_ir.Assignment(
                    [call_result], pre_ir.InvokeSubroutine("unknown_sub", [])),
                pre_ir.Assignment(
                    [derived], pre_ir.Intrinsic(
                        "+", [], [pre_ir.UInt64Constant(1), call_result], line=7)),
                pre_ir.IntrinsicOp(pre_ir.Intrinsic(
                    "itxn_field", ["Amount"], [derived], line=8)),
                pre_ir.IntrinsicOp(pre_ir.Intrinsic(
                    "itxn_field", ["Fee"], [pre_ir.Undefined("uint64")], line=9)),
                pre_ir.IntrinsicOp(pre_ir.Intrinsic(
                    "store", [3], [pre_ir.Undefined("uint64")], line=10)),
                pre_ir.Assignment(
                    [loaded], pre_ir.Intrinsic("load", [3], [], line=11)),
                pre_ir.IntrinsicOp(pre_ir.Intrinsic(
                    "log", [], [loaded], line=12)),
                pre_ir.Assert(pre_ir.Undefined("uint64")),
            ],
            pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))],
        is_main=True,
    )
    return SimpleNamespace(
        subs=[main, unknown_sub],
        name2sub={unknown_sub.id: unknown_sub},
        register_sources={},
        register_objects={
            id(unknown_value): unknown_value,
            id(call_result): call_result,
            id(derived): derived,
            id(loaded): loaded,
        },
        regs={},
        load_stores={},
    ), call_result, derived, loaded


def test_unknown_is_top_across_calls_summaries_sinks_and_custom_views():
    lifter, call_result, derived, loaded = _unknown_lifter()

    taint = user_input_taint(lifter)
    assert UNKNOWN_SOURCE in taint[id(call_result)]
    assert UNKNOWN_SOURCE in taint[id(derived)]
    assert UNKNOWN_SOURCE in taint[id(loaded)]

    summary = compute_summaries(lifter)["unknown_sub"]
    assert UNKNOWN_SOURCE in summary.internal_sources

    sinks = tainted_sinks(lifter, taint={})
    assert any(op == "itxn_field" and imm == ["Amount"] for _, op, imm in sinks)
    assert any(op == "itxn_field" and imm == ["Fee"] for _, op, imm in sinks)
    assert any(op == "assert" for _, op, _ in sinks)
    assert any(op == "log" for _, op, _ in sinks)
    report = taint_report(lifter, "unknown.teal")
    assert "Sources present   : unresolved" in report
    assert "itxn_field Amount" in report and "itxn_field Fee" in report

    # A specialised/custom source abstraction may replace attacker-input
    # labels, but never the lattice TOP introduced by the representation.
    flows = tainted_fund_flows(lifter, taint={})
    amount = [finding for finding in flows if finding.field == "Amount"]
    assert len(amount) == 1
    assert UNKNOWN_SOURCE in amount[0].sources


def test_real_unresolved_value_survives_a_scratch_round_trip(tmp_path):
    """The exact SSA reaching-def bridge must carry TOP through store/load.

    The hostile cross-band callee leaves an unrepresentable runtime value in
    the caller residual. Naming its SSA leaf with ``lifter.reg`` used to mint a
    clean orphan at the later load; ``lifter.value`` must recover the original
    explicit Undefined instead.
    """
    source = (TESTS_DIR / "contracts" / "hostile-crossband"
              / "crossband_taint_runtime.teal")
    if not source.exists():
        pytest.skip("hostile-crossband fixture not present")
    teal = source.read_text().replace(
        "pop\nitxn_begin", "pop\nstore 0\nload 0\nitxn_begin", 1)
    lifter = _lifter(teal, tmp_path)
    amounts = [finding for finding in tainted_fund_flows(lifter)
               if finding.field == "Amount"]
    assert len(amounts) == 1
    assert UNKNOWN_SOURCE in amounts[0].sources


def test_value_tuple_unknown_taint_is_positional():
    unknown, clean = (pre_ir.Register(name, 0, "uint64")
                      for name in ("unknown", "clean"))
    main = pre_ir.Subroutine(
        "main", [], [], [pre_ir.BasicBlock(
            0, [], [pre_ir.Assignment(
                [unknown, clean], pre_ir.ValueTuple([
                    pre_ir.Undefined("uint64"), pre_ir.UInt64Constant(7)]))],
            pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))], is_main=True)
    lifter = SimpleNamespace(
        subs=[main], name2sub={}, register_sources={}, register_objects={},
        regs={}, load_stores={})
    taint = user_input_taint(lifter)
    assert UNKNOWN_SOURCE in taint[id(unknown)]
    assert id(clean) not in taint
