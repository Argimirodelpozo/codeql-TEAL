"""Direct unit tests for `PathPredicateAnalysis._decompose_cond` — the boolean
connective (`&&`/`||`/`!`) decomposition that derives sub-predicates on a branch
edge. Rewritten from recursive to an iterative worklist; these pin the semantics
AND the cycle-safety the rewrite provides (a phi feeding its own guard must not
hang / overflow).
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram, SSAVar
from tealql.tealtools.ssa.models import Assignment, Location
from tealql.tealtools.path_predicates import PathPredicateAnalysis


def _by_op(p, op):
    return [a for a in p.assignments if a.op == op]


def test_and_truthy_decomposes_both_operands():
    # assert(x < 5 && y > 3): on the taken (truthy) side BOTH comparisons hold.
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\nint 5\n<\n"
            "txna ApplicationArgs 1\nbtoi\nint 3\n>\n"
            "&&\nassert\nint 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    p.propagate_constants()
    pp = PathPredicateAnalysis(p)
    cond = _by_op(p, "&&")[0].outputs[0]
    preds = pp._decompose_cond(cond, taken=True)
    kinds = {bc.kind for bc in preds}
    assert "nonzero" in kinds                    # the && itself
    assert "lt" in kinds and "gt" in kinds        # BOTH operands decomposed


def test_and_falsy_side_is_not_decomposed():
    # On the FALSY side of `&&` at least one operand is zero — a disjunction we
    # don't model, so only the bare (cond, zero) predicate is emitted.
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\nint 5\n<\n"
            "txna ApplicationArgs 1\nbtoi\nint 3\n>\n"
            "&&\nassert\nint 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    p.propagate_constants()
    pp = PathPredicateAnalysis(p)
    cond = _by_op(p, "&&")[0].outputs[0]
    preds = pp._decompose_cond(cond, taken=False)
    assert {bc.kind for bc in preds} == {"zero"}   # nothing decomposed


def test_not_inverts_truthiness():
    # !(x) taken -> x is zero.
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\n!\nassert\nint 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    p.propagate_constants()
    pp = PathPredicateAnalysis(p)
    cond = _by_op(p, "!")[0].outputs[0]
    preds = pp._decompose_cond(cond, taken=True)
    inner = _by_op(p, "btoi")[0].outputs[0]
    # the inner operand is proven ZERO on the !-taken side
    assert any(bc.value is inner and bc.kind == "zero" for bc in preds)


def test_ge_comparison_not_inverted():
    # `x >= 1000` — operands are TOP-FIRST, so a positional read would flip it to
    # `x <= 1000`. The variable-side predicate must carry kind 'ge', rhs 1000.
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\nint 1000\n>=\nassert\nint 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    p.propagate_constants()
    pp = PathPredicateAnalysis(p)
    cond = _by_op(p, ">=")[0].outputs[0]
    x = _by_op(p, "btoi")[0].outputs[0]
    preds = pp._decompose_cond(cond, taken=True)
    on_x = [bc for bc in preds if bc.value is x]
    assert on_x and on_x[0].kind == "ge"          # NOT 'le'
    assert "1000" in repr(on_x[0])                # rhs preserved


def test_lt_comparison_not_inverted():
    # symmetric check with `x < 5` -> kind 'lt' on the variable, not 'gt'.
    teal = ("#pragma version 8\n"
            "txna ApplicationArgs 0\nbtoi\nint 5\n<\nassert\nint 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    p.propagate_constants()
    pp = PathPredicateAnalysis(p)
    cond = _by_op(p, "<")[0].outputs[0]
    x = _by_op(p, "btoi")[0].outputs[0]
    on_x = [bc for bc in pp._decompose_cond(cond, taken=True) if bc.value is x]
    assert on_x and on_x[0].kind == "lt"


def test_cyclic_cond_terminates():
    # A synthetic cyclic value web (a && depends on b, b && depends on a) — the
    # recursive form would loop forever; the iterative `seen` worklist bails.
    pp = PathPredicateAnalysis.__new__(PathPredicateAnalysis)  # no analysis needed
    a = SSAVar("f.teal", 1, 1)
    b = SSAVar("f.teal", 2, 1)
    leaf = SSAVar("f.teal", 3, 1)

    def _mk(op, ins):
        return Assignment(outputs=[], op=op, immediates="", inputs=ins,
                          location=Location("f.teal", 0), ast_code=op)

    a.defined_by = _mk("&&", [b, leaf])
    b.defined_by = _mk("&&", [a, leaf])          # cycle: a -> b -> a
    preds = pp._decompose_cond(a, taken=True)
    # terminated (didn't hang / overflow) and still produced predicates
    assert isinstance(preds, frozenset)
    assert any(bc.value is a for bc in preds)


# ---------------------------------------------------------------------------
# What survives a `callsub` return
#
# `_rooted_in_immutable_fields` decides which of the caller's predicates are
# carried back across a subroutine return. It had ZERO coverage: a mutation
# sweep forcing it to True AND to False left the whole benchmark unchanged,
# which is how the OpcodeBudget hole below survived.
# ---------------------------------------------------------------------------


def _cmp_out(tmp_path, src, op=">"):
    from tealql.tealtools.ssa import SSAProgram
    p = tmp_path / "r.teal"
    p.write_text(src)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return next(a for a in prog.assignments if a.op == op).outputs[0]


def _global_cmp(tmp_path, field):
    return _cmp_out(tmp_path, f"#pragma version 8\nglobal {field}\nint 5\n>\n"
                              f"bnz ok\nint 0\nreturn\nok:\nint 1\nreturn\n")


def test_opcode_budget_is_not_immutable(tmp_path):
    """`global OpcodeBudget` DECREASES as the program runs, so a callee spends
    it and a predicate on it cannot be carried across the return — doing so
    claims a budget that has already been consumed.

    `passes/input_prop` already knew this (`_UNSTABLE_GLOBAL_FIELDS`); this
    module did not, which is the whole reason the fact now lives in `avm`."""
    from tealql.tealtools.path_predicates import _rooted_in_immutable_fields
    assert _rooted_in_immutable_fields(_global_cmp(tmp_path, "OpcodeBudget")) is False


def test_stable_globals_are_still_immutable(tmp_path):
    """Non-vacuity: the fix must not reject every global.

    `GroupSize` deliberately stays immutable. It is attacker-CHOSEN (the
    attacker assembles the group) but it does not CHANGE mid-execution — that
    is the trust question, not the stability one, and it is answered elsewhere
    (`byte_taint._CLEAN_GLOBALS`)."""
    from tealql.tealtools.path_predicates import _rooted_in_immutable_fields
    for field in ("CreatorAddress", "CurrentApplicationID", "GroupSize"):
        assert _rooted_in_immutable_fields(_global_cmp(tmp_path, field)) is True, field


def test_txn_fields_and_constants_are_immutable(tmp_path):
    from tealql.tealtools.path_predicates import _rooted_in_immutable_fields
    v = _cmp_out(tmp_path, "#pragma version 8\ntxn Fee\nint 1000\n>\nbnz ok\n"
                           "int 0\nreturn\nok:\nint 1\nreturn\n")
    assert _rooted_in_immutable_fields(v) is True


def test_state_reads_are_not_immutable(tmp_path):
    """An `app_global_get` can be rewritten by the callee, so a predicate on it
    must not cross the return."""
    from tealql.tealtools.path_predicates import _rooted_in_immutable_fields
    v = _cmp_out(tmp_path, '#pragma version 8\nbyte "k"\napp_global_get\nint 5\n>\n'
                           'bnz ok\nint 0\nreturn\nok:\nint 1\nreturn\n')
    assert _rooted_in_immutable_fields(v) is False


def test_one_unstable_leaf_poisons_the_conjunction(tmp_path):
    """Rooted-ness is a conjunction over leaves: `Creator == X && budget > 5`
    is NOT carryable, because half of it can change."""
    from tealql.tealtools.path_predicates import _rooted_in_immutable_fields
    v = _cmp_out(tmp_path,
                 "#pragma version 8\n"
                 "txn Sender\nglobal CreatorAddress\n==\n"
                 "global OpcodeBudget\nint 5\n>\n"
                 "&&\nbnz ok\nint 0\nreturn\nok:\nint 1\nreturn\n", op="&&")
    assert _rooted_in_immutable_fields(v) is False


def test_duplicate_label_does_not_invert_branch_polarity():
    """The label index must resolve a duplicate to its FIRST definition, exactly
    as ``cfg.build`` routes the branch.

    Keeping the LAST meant no successor matched the branch target, so EVERY edge
    out of the branch — including the taken one — got the fall-through
    predicate: a creator-guarded block came out asserting
    ``Sender != CreatorAddress``, and the guard vanished from the program.
    Assembler-rejected source, therefore hand-written / adversarial only, which
    is the input this tool exists for."""
    from tealql.tealtools.path_predicates import PathPredicateAnalysis
    from tealql.tealtools.ssa import SSAProgram

    src = ("#pragma version 10\ntxn Sender\nglobal CreatorAddress\n==\n"
           "bnz ok\nint 0\nreturn\n"
           "ok:\nint 1\n"        # first definition — where the branch lands
           "ok:\nint 1\nreturn\n")
    prog = SSAProgram.from_text(src, strict=False)
    analysis = PathPredicateAnalysis(prog)
    assert analysis._label_lines[("contract.teal", "ok")] == 8

    taken = prog.block_containing("contract.teal", 8)
    preds = {str(p) for p in analysis.predicates_at("contract.teal", taken.first_line)}
    # The Sender/Creator comparison itself must hold as `==` on the taken edge,
    # never as its negation. (`(… != 0)` also appears — that is the separate,
    # correct "the branch condition was truthy" predicate.)
    sender_vs_creator = {p for p in preds if "L2" in p and "L3" in p}
    assert sender_vs_creator == {"(V#1@L2 == V#1@L3)"}, preds
