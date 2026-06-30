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

import pytest

from tealtools.ssa import SSAProgram
from tealtools.lift import pre_ir
from tealtools.lift.lift import _Lifter
from tealtools.lift.taint import user_input_taint, _return_summary

TESTS_DIR = Path(__file__).resolve().parent


def _lifter(teal: str, tmp_path: Path) -> _Lifter:
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    prog = SSAProgram(str(p), verbose=False)
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
    teals = sorted((TESTS_DIR / "dbs" / "xgov-db").rglob("*.teal"))
    if not teals:
        pytest.skip("xgov fixture not present (gitignored real DB)")
    prog = SSAProgram(str(teals[0]), verbose=False)
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
