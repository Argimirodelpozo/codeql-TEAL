"""Regression gates for the 2026-07-25 full-project review.

Each test pins one bug that was CONFIRMED by probe before the fix. Grouped by
the bug, not by the module, so a future regression names the defect directly.
"""
from __future__ import annotations

import logging

import pytest

from tealql.security import DETECTORS, common
from tealql.security.scan import discover_teal_files, scan
from tealql.tealtools.language import avm
from tealql.tealtools.core.errors import TargetError, TargetNotFoundError, TealQLError
from tealql.tealtools.cfg.group import analyze, analyze_per_exit
from tealql.tealtools.analysis import DerivedProfile, derived_program
from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
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
    """The explicit ``return`` operand identifies the rejecting arm."""
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
# 5. constant-condition must not read assert-refined ranges as value facts.
# ---------------------------------------------------------------------------


def test_constant_condition_is_not_pass_order_dependent(tmp_path):
    """``propagate_assert_ranges`` tightens operands USING the asserts, so every
    asserted comparison then reads as vacuous (measured: 0 -> 87 findings on a
    real-contract sample). Refinement only narrows and cannot be undone in
    place, so the detector reads its ranges off a private rebuild and the answer
    is identical either way. See also
    ``test_constant_condition_answers_the_same_either_way`` for the case where
    the fixture actually HAS a vacuous assert."""
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
    on_fresh = [v.pretty() for v in DETECTORS["constant-condition"](fresh).detect()]

    refined = _prog(tmp_path, "b.teal", src)
    refined = derived_program(refined, DerivedProfile.GUARDED)
    assert getattr(refined, "_assert_ranges_applied", False)
    on_refined = [v.pretty() for v in DETECTORS["constant-condition"](refined).detect()]

    assert sorted(on_fresh) == sorted(on_refined)


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
    reconstruction of every program using it."""
    assert avm.op_arity("falcon_verify", "") == (3, 1)
    assert "falcon_verify" not in avm.unknown_opcodes()


# ---------------------------------------------------------------------------
# 7. Follow-ups: the items the review deferred, applied.
# ---------------------------------------------------------------------------


def test_clawback_source_is_on_the_attack_surface(tmp_path):
    """``itxn_field AssetSender`` on an axfer is the CLAWBACK source — an app
    holding clawback authority that lets a caller steer it drains any holder.
    It was absent from the sink inventory entirely."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    prog = _prog(tmp_path, "prog.teal", """#pragma version 8
itxn_begin
int axfer
itxn_field TypeEnum
txna ApplicationArgs 0
itxn_field AssetSender
itxn_submit
int 1
return
""")
    cats = {h.category for h in TaintQuery(prog).all_sinks()}
    assert "asset-clawback-source" in cats
    # and it is reachable from the attacker input, i.e. on the attack surface
    assert any(h.category == "asset-clawback-source"
               for h in TaintQuery(prog).tainted_sinks())


def test_sarif_code_flow_steps_carry_a_physical_location(tmp_path):
    """A ``threadFlowLocation`` with no ``physicalLocation`` has nowhere to
    anchor, so SARIF viewers (GitHub code scanning included) drop the whole
    code flow — the witness never reached the user."""
    import json

    from tealql.security.scan import render_sarif, scan

    src = tmp_path / "c.teal"
    src.write_text("""#pragma version 8
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
itxn_field Receiver
itxn_submit
int 1
return
""")
    doc = json.loads(render_sarif(scan(tmp_path)))
    flows = [r for r in doc["runs"][0]["results"] if "codeFlows" in r]
    assert flows, "expected at least one witness-carrying finding"
    for r in flows:
        for tf in r["codeFlows"][0]["threadFlows"]:
            for step in tf["locations"]:
                assert "physicalLocation" in step["location"]
                assert step["location"]["physicalLocation"]["region"]["startLine"]


def test_constant_condition_answers_the_same_either_way(tmp_path):
    """Upgraded from "decline" to "answer correctly": when the shared program is
    already assert-refined, ranges are read off a private rebuild."""
    src = """#pragma version 8
txn OnCompletion
int 9
<
assert
int 1
return
"""
    fresh = _prog(tmp_path, "a.teal", src)
    on_fresh = [v.pretty() for v in DETECTORS["constant-condition"](fresh).detect()]

    refined = _prog(tmp_path, "a.teal", src)   # same path -> rebuildable
    refined = derived_program(refined, DerivedProfile.GUARDED)
    assert getattr(refined, "_assert_ranges_applied", False)
    on_refined = [v.pretty() for v in DETECTORS["constant-condition"](refined).detect()]

    assert on_fresh, "fixture should have a vacuous assert (OnCompletion < 9)"
    assert sorted(on_fresh) == sorted(on_refined)


def test_detector_runners_prepare_the_program_once(tmp_path):
    """``common.prepare`` is the documented handshake; ``scan`` and the CLI's
    per-file loader both apply it, so a detector's inputs no longer depend on
    which detector ran before it."""
    from tealql.security import common

    src = tmp_path / "c.teal"
    src.write_text("#pragma version 8\nint 1\nreturn\n")
    prog = SSAProgram(str(src))
    assert common.prepare(prog) is prog
    assert getattr(prog, "_consts_propagated", False)
    common.prepare(prog)              # idempotent


def test_fund_flow_walk_reexpands_on_a_shallower_reach():
    """``_walk``'s visited map keys on the SHALLOWEST depth a register has been
    expanded at. With a plain visited set, a register first reached near the
    depth cap was expanded with almost no budget left and then permanently
    suppressed — so the same register reached shallowly through another path
    never had its subtree enumerated, and which guards the walk found depended
    on traversal order.

    Built here as: ``top = f(deep_chain, shared)`` where ``deep_chain`` bottoms
    out in ``shared`` at the depth cap, and ``shared`` itself hangs one level
    below ``top``. Whichever argument is visited first, ``leaf`` must be
    reachable."""
    from tealql.tealtools.lift import fund_flow, pre_ir

    def reg(n):
        return pre_ir.Register(name=n, version=0, ir_type="uint64")

    def_of = {}

    def define(target, *args):
        def_of[id(target)] = pre_ir.Assignment(
            targets=[target], source=pre_ir.Intrinsic("+", [], list(args)))
        return target

    leaf = reg("leaf")
    shared = define(reg("shared"), leaf)
    # Chain sized so `shared`, reached through it, lands EXACTLY on the depth
    # cap: expanded there (so a set-based `seen` marks it) with no budget left
    # for `leaf`. One link longer and it would be cut before being marked,
    # which hides the bug.
    chain = shared
    for i in range(fund_flow._WALK_MAX_DEPTH - 1):
        chain = define(reg(f"c{i}"), chain)
    # `top` reaches the deep chain FIRST and `shared` directly second.
    top = define(reg("top"), chain, shared)

    names = {r.name for r, _ in fund_flow._walk(top, def_of)}
    assert "shared" in names
    assert "leaf" in names, (
        "the shallow reach to `shared` did not re-expand, so its subtree was "
        "never enumerated"
    )
