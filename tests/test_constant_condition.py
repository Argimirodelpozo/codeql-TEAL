"""Unit tests for the constant-condition detector — guards the range layer
proves are statically fixed (vacuous / unsatisfiable asserts, dead branches).

Two layers: the pure interval comparison kernel (``_eval_cmp``) and the
detector end-to-end over in-memory TEAL, exercising that it consumes the
field-bound enrichment (OnCompletion / GroupIndex / Num* ranges) and stays
silent on genuinely satisfiable guards.
"""
from tealql.tealtools.ssa import IntRange, SSAProgram
from tealql.security import DETECTORS

from importlib import import_module

_mod = import_module("tealql.security.detections.constant_condition")
_eval_cmp = _mod._eval_cmp
Detector = DETECTORS["constant-condition"]


def _kinds(teal):
    p = SSAProgram.from_text(teal, name="t")
    return [(v.kind, v.detail) for v in Detector(p).detect()]


class TestEvalCmp:
    def test_disjoint_and_ordered(self):
        lo, hi = IntRange(0, 5), IntRange(6, 6)
        assert _eval_cmp("<=", lo, hi) == 1     # 5 <= 6 always
        assert _eval_cmp("<", lo, hi) == 1      # 5 < 6 always
        assert _eval_cmp(">", lo, hi) == 0      # never
        assert _eval_cmp("==", lo, hi) == 0     # disjoint
        assert _eval_cmp("!=", lo, hi) == 1     # disjoint

    def test_overlap_is_undecided(self):
        a, b = IntRange(0, 6), IntRange(2, 2)
        assert _eval_cmp("==", a, b) is None
        assert _eval_cmp("<", a, b) is None
        assert _eval_cmp(">=", a, b) is None

    def test_equal_singletons(self):
        s = IntRange(3, 3)
        assert _eval_cmp("==", s, s) == 1
        assert _eval_cmp("!=", s, s) == 0


class TestDetector:
    def test_vacuous_assert_on_bounded_field(self):
        # OnCompletion in [0,5] => `<= 6` is always true.
        kinds = _kinds(
            "#pragma version 8\ntxn OnCompletion\nint 6\n<=\nassert\n"
            "int 1\nreturn\n"
        )
        assert ("vacuous-assert", "OnCompletion <= 6") in kinds

    def test_unsatisfiable_assert(self):
        # OnCompletion in [0,5] => `> 10` is always false.
        kinds = _kinds(
            "#pragma version 8\ntxn OnCompletion\nint 10\n>\nassert\n"
            "int 1\nreturn\n"
        )
        assert ("unsatisfiable-assert", "OnCompletion > 10") in kinds

    def test_constant_branch(self):
        # NumAssets in [0,8] => `< 100` is always true => branch is constant.
        kinds = _kinds(
            "#pragma version 8\ntxn NumAssets\nint 100\n<\nbnz ok\n"
            "int 0\nreturn\nok:\nint 1\nreturn\n"
        )
        assert any(k == "constant-branch" for k, _ in kinds)

    def test_real_check_not_flagged(self):
        # OnCompletion == NoOp is satisfiable AND falsifiable — no finding.
        assert _kinds(
            "#pragma version 8\ntxn OnCompletion\nint 0\n==\nassert\n"
            "int 1\nreturn\n"
        ) == []

    def test_unbounded_value_not_flagged(self):
        # btoi of an arg is unconstrained — a real bound, not constant.
        assert _kinds(
            "#pragma version 8\ntxn ApplicationArgs 0\nbtoi\nint 1000000\n"
            ">=\nassert\nint 1\nreturn\n"
        ) == []

    def test_params_exists_flag_assert_is_vacuous(self):
        # `assert(exists)` after asset_params_get: the flag is [0,1], NOT
        # provably non-zero, so it must NOT be flagged (the asset may be
        # absent). Guards against over-eager use of the exists-flag seed.
        kinds = _kinds(
            "#pragma version 8\nint 0\nasset_params_get AssetTotal\n"
            "assert\npop\nint 1\nreturn\n"
        )
        assert kinds == []
