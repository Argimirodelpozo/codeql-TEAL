"""Unit tests for assert-based range refinement
(``tealql.tealtools.passes.range_assert``).

The refinement math (``_apply``) is a pure function; the soundness-critical
part is the *flow sensitivity* — a guard may tighten a var globally only when
it dominates every non-test use. We exercise that on hand-built CFGs: a linear
chain (guard dominates → refine) and a diamond (one arm bypasses the guard →
must NOT refine, or a detector could miss a finding on the bypassing path).
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import (
    Assignment,
    BasicBlock,
    Const,
    IntRange,
    Location,
    Phi,
    SSAVar,
    TealType,
)
from tealql.tealtools.passes.range_assert import _apply, propagate_assert_ranges

UMAX = (1 << 64) - 1
U64 = TealType("uint64")


# --------------------------------------------------------------------------
# _apply — the pure refinement math (X is the left operand of ``X rel Y``)
# --------------------------------------------------------------------------


class TestApply:
    def test_inequalities(self):
        x, y = IntRange(0, UMAX), IntRange(100, 100)
        assert _apply("<", x, y) == (0, 99)
        assert _apply("<=", x, y) == (0, 100)
        assert _apply(">", x, y) == (101, UMAX)
        assert _apply(">=", x, y) == (100, UMAX)

    def test_equality_intersects(self):
        assert _apply("==", IntRange(0, 6), IntRange(1, 1)) == (1, 1)
        assert _apply("==", IntRange(0, 10), IntRange(3, 7)) == (3, 7)

    def test_not_equal_only_bites_at_a_boundary(self):
        # ``x != 0`` with x in [0, N] lifts the floor; an interior hole can't
        # be represented as an interval, so it's left untouched.
        assert _apply("!=", IntRange(0, 5), IntRange(0, 0)) == (1, 5)
        assert _apply("!=", IntRange(0, 5), IntRange(5, 5)) == (0, 4)
        assert _apply("!=", IntRange(0, 5), IntRange(3, 3)) == (0, 5)

    def test_only_ever_narrows(self):
        x = IntRange(10, 20)
        lo, hi = _apply("<", x, IntRange(100, 100))  # x < 100, already < 100
        assert (lo, hi) == (10, 20)  # unchanged, never widened


# --------------------------------------------------------------------------
# Flow sensitivity — hand-built CFGs
# --------------------------------------------------------------------------


class _Prog:
    """Minimal stand-in for SSAProgram: the pass only reads ``.assignments``
    / ``.phis`` and honours the ``_range_arith_propagated`` short-circuit."""

    def __init__(self, assignments):
        self.assignments = assignments
        self.phis = {}
        self._range_arith_propagated = True  # skip the range_arith lazy-trip


def _block(line):
    b = BasicBlock("f.teal", line, line)
    return b


def _u64_var(line):
    v = SSAVar("f.teal", line, 0)
    v.type = U64
    return v


def _cmp_assert(x, bound, op, block, cmp_line, assert_line):
    """Append ``assert(x op bound)`` to ``block`` (top-first inputs)."""
    cond = SSAVar("f.teal", cmp_line, 1)
    d = Assignment(
        outputs=[cond], op=op, immediates="",
        inputs=[Const("int", str(bound)), x],  # [top=bound, deeper=x] => x op bound
        location=Location("f.teal", cmp_line), ast_code=op,
        const=None, basic_block=block,
    )
    cond.defined_by = d
    a = Assignment(
        outputs=[], op="assert", immediates="", inputs=[cond],
        location=Location("f.teal", assert_line), ast_code="assert",
        const=None, basic_block=block,
    )
    block.assignments += [d, a]
    x.uses.append(d)
    return d, a


def _use(x, block, line):
    out = SSAVar("f.teal", line, 9)
    u = Assignment(
        outputs=[out], op="+", immediates="", inputs=[x, Const("int", "1")],
        location=Location("f.teal", line), ast_code="+",
        const=None, basic_block=block,
    )
    block.assignments.append(u)
    x.uses.append(u)
    return u


class TestFlowSensitivity:
    def test_linear_guard_refines(self):
        # b0:[assert(x<100)] -> b1:[use(x)]   guard dominates the use.
        b0, b1 = _block(1), _block(10)
        b0.successors, b1.predecessors = [b1], [b0]
        x = _u64_var(1)
        d, a = _cmp_assert(x, 100, "<", b0, cmp_line=2, assert_line=3)
        _use(x, b1, 11)
        prog = _Prog(b0.assignments + b1.assignments)

        assert propagate_assert_ranges(prog) == 1
        assert x.range is not None and (x.range.lo, x.range.hi) == (0, 99)

    def test_diamond_bypass_does_not_refine(self):
        # b0 -> {bA:[assert(x<100); use], bB:[use]} -> bM
        # bB bypasses the guard, so x must stay unrefined (soundness).
        b0, bA, bB, bM = _block(1), _block(10), _block(20), _block(30)
        b0.successors = [bA, bB]
        bA.predecessors, bB.predecessors = [b0], [b0]
        bA.successors, bB.successors = [bM], [bM]
        bM.predecessors = [bA, bB]
        x = _u64_var(1)
        _cmp_assert(x, 100, "<", bA, cmp_line=11, assert_line=12)
        _use(x, bA, 13)   # dominated use (after the assert in bA)
        _use(x, bB, 21)   # BYPASSING use — the reason we must not refine
        prog = _Prog(bA.assignments + bB.assignments)

        assert propagate_assert_ranges(prog) == 0
        assert x.range is None  # untouched

    def test_same_block_use_after_assert_refines(self):
        # A use in the guard's own block counts as dominated iff it is
        # strictly after the assert in source order.
        b0 = _block(1)
        x = _u64_var(1)
        _cmp_assert(x, 100, "<", b0, cmp_line=2, assert_line=3)
        _use(x, b0, 4)  # line 4 > assert line 3 => dominated
        prog = _Prog(list(b0.assignments))

        assert propagate_assert_ranges(prog) == 1
        assert (x.range.lo, x.range.hi) == (0, 99)

    def test_use_before_assert_blocks_refinement(self):
        # A non-test use *before* the assert (same block) is not dominated,
        # so the guard can't be trusted to constrain it.
        b0 = _block(1)
        x = _u64_var(1)
        _use(x, b0, 1)  # line 1 < assert line 3 => not dominated
        _cmp_assert(x, 100, "<", b0, cmp_line=2, assert_line=3)
        prog = _Prog(list(b0.assignments))

        assert propagate_assert_ranges(prog) == 0
        assert x.range is None

    def test_truthiness_assert_lifts_floor(self):
        # b0:[assert(x)] -> b1:[use(x)]  proves x != 0.
        b0, b1 = _block(1), _block(10)
        b0.successors, b1.predecessors = [b1], [b0]
        x = _u64_var(1)
        a = Assignment(
            outputs=[], op="assert", immediates="", inputs=[x],
            location=Location("f.teal", 2), ast_code="assert",
            const=None, basic_block=b0,
        )
        b0.assignments.append(a)
        x.uses.append(a)
        _use(x, b1, 11)
        prog = _Prog(b0.assignments + b1.assignments)

        assert propagate_assert_ranges(prog) == 1
        assert (x.range.lo, x.range.hi) == (1, UMAX)


class TestPhiFedIsNeverNarrowed:
    """The OTHER half of the soundness gate, and the half no test reached.

    ``narrowing_is_sound`` refuses on two grounds: an undominated use (covered
    above) and a phi-fed value. The second exists because the dominance check
    walks ``x.uses``, which holds only OP uses — a phi consumer is invisible to
    it. So a value can pass the dominance test while flowing, via a phi arg,
    down a predecessor edge that never touched the guard.

    Both tests below build the CFG of ``test_linear_guard_refines``, which DOES
    refine, and add nothing but the phi edge. Any difference in outcome is
    attributable to that edge alone."""

    def _linear_guarded_var(self):
        b0, b1 = _block(1), _block(10)
        b0.successors, b1.predecessors = [b1], [b0]
        x = _u64_var(1)
        _cmp_assert(x, 100, "<", b0, cmp_line=2, assert_line=3)
        _use(x, b1, 11)
        return x, _Prog(b0.assignments + b1.assignments)

    def test_control_refines_without_the_phi(self):
        """Non-vacuity: this construction narrows when nothing is phi-fed."""
        x, prog = self._linear_guarded_var()
        assert propagate_assert_ranges(prog) == 1
        assert (x.range.lo, x.range.hi) == (0, 99)

    def test_phi_arg_blocks_refinement(self):
        x, prog = self._linear_guarded_var()
        ph = Phi("f.teal", 30, 1)
        ph.args = [x, Const("int", "7")]
        prog.phis = {("f.teal", 30, 1): ph}

        assert propagate_assert_ranges(prog) == 0
        assert x.range is None


# --------------------------------------------------------------------------
# Integration — real guards on the xgov fixture
# --------------------------------------------------------------------------


def _xgov():
    contract = Path(__file__).parent / "contracts" / "xgov"
    if not contract.exists():
        pytest.skip("xgov fixture not present")
    from tealql.tealtools.ssa import SSAProgram

    try:
        return SSAProgram(str(contract))
    except Exception as e:  # pragma: no cover
        pytest.skip(f"could not build SSAProgram: {e}")


class TestXgovIntegration:
    def test_guards_tighten_known_invariants(self):
        prog = _xgov()
        n = propagate_assert_ranges(prog)
        assert n > 0

        ranges = {
            (o.line, o.index): (o.range.lo, o.range.hi)
            for a in prog.assignments for o in a.outputs
            if isinstance(o, SSAVar) and o.range is not None
        }
        flat = set(ranges.values())
        # ``== appl`` collapses an enum [0, 6] to exactly 1.
        assert (1, 1) in flat
        # a ``>= 100000`` minimum-amount guard installs the floor.
        assert any(lo == 100000 for lo, _ in flat)
        # a non-zero guard lifts a floor to 1 with the full ceiling.
        assert (1, UMAX) in flat

    def test_idempotent(self):
        prog = _xgov()
        propagate_assert_ranges(prog)
        assert propagate_assert_ranges(prog) == 0


class TestShuffleUsesInvariant:
    """Regression: `propagate_stack_shuffles` must keep the `.uses` invariant, or
    a value that is asserted and then `dup`'d/reused fails to tighten — range_assert
    walks `x.uses` for its dominance check, and a STALE dead-`dup` use (which is
    not dominated by the assert) would wrongly block the refinement."""

    def _prog(self, teal):
        from tealql.tealtools.ssa import SSAProgram
        p = SSAProgram.from_text(teal, name="t")
        p.propagate_constants()
        p.propagate_inputs()
        p.propagate_stack_shuffles()
        p.propagate_assert_ranges()
        return p

    def test_asserted_then_dupd_value_tightens(self):
        # L is asserted `<= 8`, then flows (through a dup) to a second consumer.
        # After shuffle-prop both readers are L directly; range_assert must tighten.
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\nbtoi\ndup\nint 8\n<=\nassert\n"
                "int 2\n*\npop\nint 1\nreturn\n")
        p = self._prog(teal)
        L = [a for a in p.assignments if a.op == "btoi"][0].outputs[0]
        # .uses reflects LIVE consumers only — the dead `dup` is excluded.
        assert all(u.op != "dup" for u in L.uses)
        assert L.range is not None and L.range.hi == 8      # tightened by assert

    def test_uses_are_rebuilt_not_duplicated(self):
        # A value read once, dup'd: after shuffle-prop its live uses are the real
        # downstream ops, never the dead dup.
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\nbtoi\ndup\nint 1\n+\nswap\nint 2\n+\n"
                "pop\npop\nint 1\nreturn\n")
        p = self._prog(teal)
        L = [a for a in p.assignments if a.op == "btoi"][0].outputs[0]
        assert all(not u.shuffled for u in L.uses)          # no dead shuffle in uses
        assert {u.op for u in L.uses} <= {"+"}              # only the live adds
