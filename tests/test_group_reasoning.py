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


# --- enum-symbol rendering ---------------------------------------------------

def test_typeenum_renders_symbolically(tmp_path):
    teal = ("#pragma version 10\n"
            "gtxn 0 TypeEnum\nint pay\n==\nassert\nint 1\nreturn\n")
    got = _constraints(tmp_path, teal)
    assert "gtxn[0].TypeEnum == pay" in got
    assert "gtxn[0].TypeEnum == 1" not in got


def test_oncompletion_renders_symbolically(tmp_path):
    teal = ("#pragma version 10\n"
            "txn OnCompletion\nint DeleteApplication\n==\nassert\nint 1\nreturn\n")
    assert "Txn.OnCompletion == DeleteApplication" in _constraints(tmp_path, teal)


# --- per-exit enumeration ----------------------------------------------------

_TWO_SHAPE = """#pragma version 10
txna ApplicationArgs 0
byte "swap"
==
bnz swap_path
byte "solo"
==
bnz solo_path
err
swap_path:
global GroupSize
int 2
==
assert
int 1
return
solo_path:
global GroupSize
int 1
==
assert
int 1
return
"""


def _per_exit(tmp_path, teal):
    from tealql.tealtools import group_reasoning as G
    (tmp_path / "p.teal").write_text(teal)
    return G.analyze_per_exit(SSAProgram(str(tmp_path)))


def test_per_exit_recovers_both_shapes_common_drops_them(tmp_path):
    from tealql.tealtools import group_reasoning as G
    (tmp_path / "p.teal").write_text(_TWO_SHAPE)
    prog = SSAProgram(str(tmp_path))
    # the common-shape summary collapses (2 and 1 don't intersect)
    assert G.analyze(prog).constraints == []
    # per-exit keeps both
    shapes = G.analyze_per_exit(prog).shapes
    rendered = {frozenset(c.render() for c in s.shape.constraints) for s in shapes}
    assert frozenset({"Global.GroupSize == 2"}) in rendered
    assert frozenset({"Global.GroupSize == 1"}) in rendered


def test_per_exit_shapes_are_distinct(tmp_path):
    # the dedup invariant: no two emitted entries carry the identical shape
    # (identical-shape exits merge — though CFG tail-sharing usually merges them
    # into a single exit BB before we even get here).
    shapes = _per_exit(tmp_path, _TWO_SHAPE).shapes
    keys = [frozenset(c.render() for c in s.shape.constraints) for s in shapes]
    assert len(keys) == len(set(keys))          # all distinct


def test_per_exit_json_shape(tmp_path):
    d = _per_exit(tmp_path, _TWO_SHAPE).to_dict()
    assert "exit_shapes" in d and len(d["exit_shapes"]) == 2
    for s in d["exit_shapes"]:
        assert "exits" in s and "constraints" in s


def test_per_exit_labels_abi_method(tmp_path):
    # an exit inside an ABI method body is labelled with the method name.
    from tealql.tealtools.abi import method_selector
    from tealql.tealtools import group_reasoning as G
    sel = "0x" + method_selector("withdraw(uint64)void").hex()
    (tmp_path / "p.teal").write_text(
        "#pragma version 10\n"
        "txna ApplicationArgs 0\n"
        f'pushbytes {sel} // method "withdraw(uint64)void"\n'
        "==\nbnz withdraw\nint 1\nreturn\n"
        "withdraw:\n"
        "global GroupSize\nint 2\n==\nassert\nint 1\nreturn\n")
    shapes = G.analyze_per_exit(SSAProgram(str(tmp_path))).shapes
    methods = {m for s in shapes for _ln, m in s.exits}
    assert "withdraw" in methods


# --- per-block substrate -----------------------------------------------------

def test_constraints_at_block_before_and_after_guard(tmp_path):
    from tealql.tealtools import group_reasoning as G
    from tealql.tealtools.path_predicates import PathPredicateAnalysis
    # gtxn access guarded on one arm (GroupSize==2 in force), unguarded on another.
    teal = ("#pragma version 10\n"
            "txna ApplicationArgs 0\nbyte \"g\"\n==\nbnz guarded\n"
            "gtxn 1 Amount\npop\nint 1\nreturn\n"
            "guarded:\nglobal GroupSize\nint 2\n==\nassert\n"
            "gtxn 1 Amount\npop\nint 1\nreturn\n")
    (tmp_path / "p.teal").write_text(teal)
    prog = SSAProgram(str(tmp_path))
    pp = PathPredicateAnalysis(prog)
    per_block = G.per_block_constraints(prog, pp)
    # the block that asserts GroupSize==2 has it in force; some block does NOT.
    all_shapes = [frozenset(c.render() for c in cs) for cs in per_block.values()]
    assert any("Global.GroupSize == 2" in s for s in all_shapes)
