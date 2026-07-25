"""Regression gates for the 2026-07-25 full-project review.

Each test pins one bug that was CONFIRMED by probe before the fix. Grouped by
the bug, not by the module, so a future regression names the defect directly.
"""
from __future__ import annotations

import logging

import pytest

from tealql.security import DETECTORS, common
from tealql.security.scan import discover_teal_files, scan
from tealql.tealtools import avm, cost_analysis
from tealql.tealtools.errors import TargetError, TargetNotFoundError, TealQLError
from tealql.tealtools.group_reasoning import analyze, analyze_per_exit
from tealql.tealtools.passes import run_all_passes
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return prog


def _rekey(prog):
    return DETECTORS["rekey-to"](prog, file=None).detect()


# ---------------------------------------------------------------------------
# 1. Branch polarity: `cmp; bnz <reject>` is a guard, and so is its bz mirror.
# ---------------------------------------------------------------------------

# The four ways a comparison can gate rejection. All four pin RekeyTo to the
# zero address on the approving path, so none of them is a finding.
_GUARDED_SHAPES = {
    # cond FALSE rejects — the two shapes that already worked.
    "bz_target_rejects": """#pragma version 8
txn RekeyTo
global ZeroAddress
==
bz fail
int 1
return
fail:
err
""",
    "bnz_fallthrough_rejects": """#pragma version 8
txn RekeyTo
global ZeroAddress
==
bnz ok
err
ok:
int 1
return
""",
    # cond TRUE rejects, condition NEGATED — the two shapes that did not.
    "bnz_target_rejects_neq": """#pragma version 8
txn RekeyTo
global ZeroAddress
!=
bnz fail
int 1
return
fail:
err
""",
    "bz_fallthrough_rejects_neq": """#pragma version 8
txn RekeyTo
global ZeroAddress
!=
bz ok
err
ok:
int 1
return
""",
}


@pytest.mark.parametrize("shape", sorted(_GUARDED_SHAPES))
def test_every_rejection_polarity_counts_as_a_rekey_guard(tmp_path, shape):
    """``!=; bnz fail`` pins RekeyTo to zero exactly as well as ``==; assert``.
    Only the "cond FALSE rejects" rows used to be recognised, so the idiomatic
    hand-written form reported a correctly-guarded LogicSig as vulnerable."""
    prog = _prog(tmp_path, "prog.teal", _GUARDED_SHAPES[shape])
    assert _rekey(prog) == [], f"{shape}: a real RekeyTo guard read as absent"


def test_inverted_equality_guard_is_still_a_finding(tmp_path):
    """The counterpart that must KEEP firing: ``==; bz approve`` approves on the
    FALSE side, i.e. it requires ``RekeyTo != ZeroAddress`` — the check is
    inverted and mandates the drain. Widening polarity must not swallow it."""
    prog = _prog(tmp_path, "prog.teal", """#pragma version 8
txn RekeyTo
global ZeroAddress
==
bz approve
int 0
return
approve:
int 1
return
""")
    assert len(_rekey(prog)) == 1


# ---------------------------------------------------------------------------
# 2. `int 0; return` reject arms are not approving exits.
# ---------------------------------------------------------------------------

_REJECT_ARM = """#pragma version 8
txna ApplicationArgs 0
byte "ok"
==
bz reject
global GroupSize
int 2
==
assert
int 1
return
reject:
int 0
return
"""


def test_reject_arm_is_not_an_approving_exit(tmp_path):
    """``return``'s modelled arity is ``(0, 0)``, so the old
    ``last.inputs[0] == 0`` test could never fire and every ``int 0; return``
    counted as an approval."""
    prog = _prog(tmp_path, "prog.teal", _REJECT_ARM)
    exits = PathPredicateAnalysis(prog).approving_exits()
    assert len(exits) == 1
    assert not common.is_approval_exit(
        next(bb for bb in prog.blocks.values() if bb not in exits
             and bb.assignments and bb.assignments[-1].op == "return"))


def test_group_shape_survives_a_reject_arm(tmp_path):
    """The reject arm's facts used to be intersected into the common shape,
    erasing it entirely."""
    prog = _prog(tmp_path, "prog.teal", _REJECT_ARM)
    rendered = analyze(prog).render()
    assert "GroupSize == 2" in rendered
    # ...and the reject arm is no longer offered as an admissible group shape.
    assert len(analyze_per_exit(prog).shapes) == 1


# ---------------------------------------------------------------------------
# 3. Diamond-shaped value flow must not hide a guard.
# ---------------------------------------------------------------------------

_DIAMOND = """#pragma version 8
txn RekeyTo
store 2
load 2
store 3
txna ApplicationArgs 0
btoi
bnz alt
load 3
b join
alt:
load 3
join:
global ZeroAddress
==
assert
int 1
return
"""

_LINEAR = """#pragma version 8
txn RekeyTo
store 2
load 2
store 3
load 3
global ZeroAddress
==
assert
int 1
return
"""


def test_guard_joined_over_a_shared_node_is_still_seen(tmp_path):
    """Both arms of the phi trace back through the SAME intermediate load. The
    MUST-walk's cycle-break set doubled as a memo, so the second arm hit
    "already seen" and answered False, collapsing the conjunction and hiding a
    guard the linear form recognises."""
    assert _rekey(_prog(tmp_path, "linear.teal", _LINEAR)) == []
    assert _rekey(_prog(tmp_path, "diamond.teal", _DIAMOND)) == []


# ---------------------------------------------------------------------------
# 4. A scan of a bad root must not read as clean.
# ---------------------------------------------------------------------------


def test_scan_refuses_a_missing_root(tmp_path):
    with pytest.raises(TargetNotFoundError):
        discover_teal_files(tmp_path / "nope")


def test_scan_refuses_a_file_as_root(tmp_path):
    f = tmp_path / "x.teal"
    f.write_text("#pragma version 8\nint 1\nreturn\n")
    with pytest.raises(TargetError):
        discover_teal_files(f)


def test_scan_of_an_empty_dir_warns_and_strict_refuses(tmp_path, caplog):
    empty = tmp_path / "empty"
    empty.mkdir()
    with caplog.at_level(logging.WARNING, logger="tealql.security.scan"):
        assert scan(empty) == []
    assert "nothing was analyzed" in caplog.text
    with pytest.raises(TealQLError):
        scan(empty, strict=True)


# ---------------------------------------------------------------------------
# 5. constant-condition must not run on assert-refined ranges.
# ---------------------------------------------------------------------------


def test_constant_condition_declines_after_assert_refinement(tmp_path):
    """``propagate_assert_ranges`` tightens operands USING the asserts, so every
    asserted comparison then reads as vacuous (measured: 0 -> 87 findings on a
    real-contract sample). The detector cannot un-refine, so it declines."""
    src = """#pragma version 8
txna ApplicationArgs 0
btoi
dup
int 10
<
assert
int 20
<
assert
int 1
return
"""
    fresh = _prog(tmp_path, "a.teal", src)
    baseline = DETECTORS["constant-condition"](fresh, file=None).detect()

    refined = _prog(tmp_path, "b.teal", src)
    run_all_passes(refined)
    assert getattr(refined, "_assert_ranges_applied", False)
    assert DETECTORS["constant-condition"](refined, file=None).detect() == []
    # The fresh program's answer is whatever it is — the point is that the
    # refined one does not invent findings on top of it.
    assert isinstance(baseline, list)


# ---------------------------------------------------------------------------
# 6. AVM metadata: app-only opcodes and the falcon_verify hole.
# ---------------------------------------------------------------------------


def test_account_query_opcodes_prove_an_application(tmp_path):
    """``balance`` / ``min_balance`` / ``gaid`` are Application-mode only, but
    were missing from the app-only set — so a contract using only those
    classified as a LOGICSIG and got the lsig-only detectors run against it."""
    prog = _prog(tmp_path, "prog.teal", """#pragma version 8
txn Sender
balance
int 100000
>
assert
int 1
return
""")
    assert common.classify_program(prog) == "app"
    for op in ("balance", "min_balance", "gaid", "gaids",
               "voter_params_get", "online_stake"):
        assert op in avm.APP_ONLY_OPS


def test_falcon_verify_is_modelled():
    """Absent from SIG it was ``(0, 0)`` — no stack effect — which corrupts the
    reconstruction of every program using it, and it was charged cost 1."""
    assert avm.op_arity("falcon_verify", "") == (3, 1)
    assert cost_analysis.opcode_cost("falcon_verify") == 1700
    assert "falcon_verify" not in avm.unknown_opcodes()


@pytest.mark.parametrize("op,cost", [
    ("mimc", 10), ("sumhash512", 150), ("json_ref", 25),
])
def test_length_scaled_ops_are_no_longer_charged_one(op, cost):
    assert cost_analysis.opcode_cost(op) == cost
    assert op in cost_analysis.LENGTH_SCALED_OPS


def test_cost_report_flags_inexact_ops(tmp_path):
    prog = _prog(tmp_path, "prog.teal", """#pragma version 11
txna ApplicationArgs 0
mimc BN254Mp110
pop
int 1
return
""")
    assert cost_analysis.length_scaled_ops_used(prog) == ["mimc"]
    assert "LOWER bound" in cost_analysis.render(prog)
    assert cost_analysis.to_dict(prog)["inexact_cost_ops"] == ["mimc"]
