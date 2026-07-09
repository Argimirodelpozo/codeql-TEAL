"""Prototype: bottom-up interprocedural procedure summaries.

Pins the two facts the shared fixpoint computes — taint transfer (passthrough
params + internal sources) and the NEW guard fact (params asserted
unconditionally) — plus the equivalence of the taint half with the existing
production summary (``taint._return_summary``) on real contracts.
"""
from __future__ import annotations

import glob

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift.lift import _Lifter                 # noqa: E402
from tealql.tealtools.lift.summaries import compute_summaries  # noqa: E402
from tealql.tealtools.lift.taint import _return_summary        # noqa: E402
from tealql.tealtools.ssa import SSAProgram                    # noqa: E402


def _summaries(tmp_path, teal: str):
    (tmp_path / "p.teal").write_text(teal)
    p = SSAProgram(str(tmp_path))
    p.propagate_constants()
    lf = _Lifter(p)
    lf.build()
    by_id = compute_summaries(lf)
    # name -> summary, for readable assertions
    return {s.id: by_id[s.id] for s in lf.subs if not s.is_main}


_PASSTHROUGH_AND_GUARD = """#pragma version 10
txna ApplicationArgs 0
callsub validate
txna ApplicationArgs 1
callsub identity
pop
int 1
return

validate:
proto 1 0
frame_dig -1
txn Sender
==
assert
retsub

identity:
proto 1 1
frame_dig -1
retsub
"""


def test_passthrough_and_guard_facts(tmp_path):
    summ = _summaries(tmp_path, _PASSTHROUGH_AND_GUARD)
    by_name = {sid: s for sid, s in summ.items()}
    validate = next(s for sid, s in by_name.items() if "validate" in sid)
    identity = next(s for sid, s in by_name.items() if "identity" in sid)
    # validate(x): asserts x == Sender, returns nothing.
    assert validate.checked_params == frozenset({0})
    assert validate.passthrough == frozenset()
    # identity(x): returns x, checks nothing.
    assert identity.passthrough == frozenset({0})
    assert identity.checked_params == frozenset()


def test_internal_source_taints_return_regardless_of_args(tmp_path):
    """A subroutine that reads ApplicationArgs INTERNALLY returns a tainted value
    independent of its (here absent) parameters — captured as internal_sources,
    not passthrough."""
    teal = """#pragma version 10
callsub read_arg
pop
int 1
return

read_arg:
proto 0 1
txna ApplicationArgs 0
retsub
"""
    summ = _summaries(tmp_path, teal)
    read_arg = next(iter(summ.values()))
    assert read_arg.internal_sources, "internal ApplicationArgs read must be a source"
    assert read_arg.passthrough == frozenset()


def test_guard_only_when_unconditional(tmp_path):
    """An assert on a param behind a branch is NOT (yet) a guard fact — the
    prototype recognises only entry-block (always-executed) asserts, so it stays
    sound (never claims a param is validated when a path skips the assert)."""
    teal = """#pragma version 10
txna ApplicationArgs 0
callsub maybe_check
int 1
return

maybe_check:
proto 1 0
frame_dig -1
txn NumAppArgs
int 0
==
bz skip
frame_dig -1
txn Sender
==
assert
skip:
retsub
"""
    summ = _summaries(tmp_path, teal)
    maybe = next(iter(summ.values()))
    assert 0 not in maybe.checked_params, "branch-guarded param must not read as validated"


@pytest.mark.parametrize("contract", [
    "tests/contracts/repro",
    "tests/contracts/folks-consensus-v2",
])
def test_taint_fact_equivalent_to_production_summary(contract):
    """The framework's taint half reproduces taint._return_summary exactly on real
    contracts (so it can replace/back it), while additionally carrying guards."""
    if not glob.glob(contract + "/*.teal"):
        pytest.skip("contract fixture not present")
    p = SSAProgram(contract)
    p.propagate_constants()
    lf = _Lifter(p)
    lf.build()
    mine = compute_summaries(lf)
    ref = _return_summary(lf)
    for sid, (rsrcs, rparams) in ref.items():
        assert mine[sid].internal_sources == rsrcs, sid
        assert mine[sid].passthrough == rparams, sid


# --- the summary WIRED into fund-flow: a callee that validates its param
#     internally guards the caller's value across the callsub ---

_CALLEE_VALIDATES = """#pragma version 10
txna ApplicationArgs 0
dup
callsub validate
itxn_begin
int pay
itxn_field TypeEnum
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return

validate:
proto 1 0
frame_dig -1
txn Sender
==
assert
retsub
"""

_CALLEE_NOOP = """#pragma version 10
txna ApplicationArgs 0
dup
callsub noop
itxn_begin
int pay
itxn_field TypeEnum
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return

noop:
proto 1 0
retsub
"""


def _fund_findings(tmp_path, teal):
    from tealql.security import DETECTORS
    (tmp_path / "p.teal").write_text(teal)
    return DETECTORS["ir-tainted-fund-flow"](SSAProgram(str(tmp_path))).detect()


def test_callee_internal_validation_guards_across_callsub(tmp_path):
    """A caller-supplied Receiver passed to a helper that asserts it == Sender is
    NOT an attacker-controlled fund flow — the callee-param guard summary transfers
    the guard across the callsub (was a false positive before wiring)."""
    assert _fund_findings(tmp_path, _CALLEE_VALIDATES) == []


def test_callee_without_validation_still_flags(tmp_path):
    """Control: the same shape but the callee does NOT validate → still flagged
    (the transfer doesn't over-suppress)."""
    assert len(_fund_findings(tmp_path, _CALLEE_NOOP)) == 1
