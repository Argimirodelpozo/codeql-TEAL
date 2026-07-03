"""Unit tests for forward range arithmetic (``tealql.tealtools.passes.range_arith``),
focused on the two behaviours added on top of the stdlib seeds: const→range
seeding and the top-first operand order of the non-commutative ops.

These build tiny ``Assignment`` lists directly and short-circuit the
``propagate_ranges`` lazy-trip (``_ranges_propagated = True``), so no CodeQL DB
is needed.
"""
from tealql.tealtools.ssa import Assignment, Const, Location, SSAVar
from tealql.tealtools.passes.range_arith import propagate_range_arithmetic


class _FakeProg:
    def __init__(self, assignments):
        self.assignments = assignments
        self.phis = {}
        self._ranges_propagated = True  # skip the stdlib seed (needs a real graph)


def _const_assign(op, out, *inputs, imm=""):
    return Assignment(
        outputs=[out], op=op, immediates=imm, inputs=list(inputs),
        location=Location("f.teal", 1), ast_code=op, const=None, basic_block=None,
    )


def _rng(v):
    return None if v.range is None else (v.range.lo, v.range.hi)


class TestConstSeed:
    def test_const_value_gets_singleton_range(self):
        # A var const-folded to a literal int N must carry the exact range
        # [N, N]; the stdlib seeds (op/field shape) never give const vars one.
        out = SSAVar("f.teal", 1, 0)
        out.const_value = Const("int", "5")
        prog = _FakeProg([_const_assign("intc_0", out)])
        propagate_range_arithmetic(prog)
        assert _rng(out) == (5, 5)

    def test_bytes_const_stays_unranged(self):
        out = SSAVar("f.teal", 1, 0)
        out.const_value = Const("bytes", "0xdeadbeef")
        prog = _FakeProg([_const_assign("bytec_0", out)])
        propagate_range_arithmetic(prog)
        assert out.range is None


class TestTopFirstOperands:
    """``Assignment.inputs`` are top-first, so for ``A op B`` (A deeper)
    ``inputs = [B, A]``. range_arith must compute ``A op B``, not ``B op A``."""

    def test_subtraction_is_deeper_minus_top(self):
        # TEAL ``int 100; int 30; -`` => 100 - 30 = 70.  inputs = [30, 100].
        out = SSAVar("f.teal", 1, 0)
        prog = _FakeProg([
            _const_assign("-", out, Const("int", "30"), Const("int", "100")),
        ])
        propagate_range_arithmetic(prog)
        assert _rng(out) == (70, 70)

    def test_reversed_order_would_underflow_to_no_range(self):
        # ``int 30; int 100; -`` underflows (30 - 100) and halts — no range.
        # Catches a regression to deepest-first (which would fold 100 - 30 = 70).
        out = SSAVar("f.teal", 1, 0)
        prog = _FakeProg([
            _const_assign("-", out, Const("int", "100"), Const("int", "30")),
        ])
        propagate_range_arithmetic(prog)
        assert out.range is None

    def test_division_is_deeper_over_top(self):
        # ``int 100; int 4; /`` => 100 / 4 = 25.  inputs = [4, 100].
        out = SSAVar("f.teal", 1, 0)
        prog = _FakeProg([
            _const_assign("/", out, Const("int", "4"), Const("int", "100")),
        ])
        propagate_range_arithmetic(prog)
        assert _rng(out) == (25, 25)
