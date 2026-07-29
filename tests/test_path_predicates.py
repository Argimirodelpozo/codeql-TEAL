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
