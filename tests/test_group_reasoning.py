"""Group-shape reasoning (`tealtools.group_reasoning`).

Covers the comparator-direction correctness fix (top-first operands must not
invert a non-commutative relation) at the `derive_constraint` level.
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools import group_reasoning as G


def _constraints(tmp_path, teal):
    (tmp_path / "p.teal").write_text(teal)
    prog = SSAProgram(str(tmp_path))
    pp = PathPredicateAnalysis(prog)
    out = []
    for bb in pp.approving_exits():
        for pred in pp.bb_preds.get(bb, frozenset()):
            c = G.derive_constraint(pred)
            if c is not None:
                out.append(c.render())
    return out


def test_ge_constraint_direction(tmp_path):
    # gtxn 0 Amount >= 1000 must derive `>= 1000`, not the inverted `<= 1000`.
    teal = ("#pragma version 10\n"
            "gtxn 0 Amount\nint 1000\n>=\nassert\nint 1\nreturn\n")
    assert "gtxn[0].Amount >= 1000" in _constraints(tmp_path, teal)
    assert "gtxn[0].Amount <= 1000" not in _constraints(tmp_path, teal)


def test_lt_constraint_direction(tmp_path):
    teal = ("#pragma version 10\n"
            "gtxn 0 Amount\nint 5000\n<\nassert\nint 1\nreturn\n")
    got = _constraints(tmp_path, teal)
    assert "gtxn[0].Amount < 5000" in got
    assert "gtxn[0].Amount > 5000" not in got


def test_eq_constraint_still_correct(tmp_path):
    # `==` is symmetric — the fix must not disturb it.
    teal = ("#pragma version 10\n"
            "global GroupSize\nint 2\n==\nassert\nint 1\nreturn\n")
    assert "Global.GroupSize == 2" in _constraints(tmp_path, teal)
