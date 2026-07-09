"""Property-based SOUNDNESS of the IntRange arithmetic kernel.

The other range tests assert "computed bound == author-expected bound" — written
by the same author as the kernel, so they agree with a wrong bound. This checks
the property that actually matters: for any operand ranges, EVERY concrete input
pair that SUCCESSFULLY executes must produce a result inside the propagated range.
The concrete oracle is ``const_fold`` (exact AVM semantics), so an unsound bound
(too tight, an overflow that doesn't wrap, an off-by-one on ``%`` / ``<<``) — the
exact bug that would silently narrow an attacker-reachable value out of a guard —
fails here with a minimal counterexample.

A concrete pair that HALTS at runtime (uint64 overflow on ``+``/``*``, underflow
on ``-``, divide-by-zero) makes ``const_fold`` return ``None``; there is no result
to bound, so it's skipped — matching the kernel's "reasons only about successful
executions" contract.
"""
from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings                       # noqa: E402
from hypothesis import strategies as st                      # noqa: E402

from tealql.tealtools.passes.range_arith import (            # noqa: E402
    _arith_result_range,
    _clamp_uint64,
    _unary_result_range,
)
from tealql.tealtools.ssa import IntRange                    # noqa: E402
from tealql.tealtools.ssa.const_fold import (                # noqa: E402
    _fold_bitwise,
    _fold_bitwise_not,
    _fold_int_arith,
    _int_const,
    _int_from_const,
)

MAX = 2 ** 64 - 1
_ARITH = ("+", "-", "*", "/", "%")
_BITWISE = ("&", "|", "^", "<<", ">>")


@st.composite
def _range_and_value(draw):
    """An ``IntRange`` over uint64 plus a concrete value inside it — so the
    concrete input is a member of the range by construction."""
    lo = draw(st.integers(min_value=0, max_value=MAX))
    hi = draw(st.integers(min_value=lo, max_value=MAX))
    v = draw(st.integers(min_value=lo, max_value=hi))
    return IntRange(lo, hi), v


def _concrete(op, a, b):
    fold = _fold_int_arith if op in _ARITH else _fold_bitwise
    r = fold(op, [_int_const(a), _int_const(b)])
    return None if r is None else _int_from_const(r)


@settings(max_examples=800)
@given(_range_and_value(), _range_and_value(), st.sampled_from(_ARITH + _BITWISE))
def test_binary_range_contains_every_concrete_result(av, bv, op):
    ra, a = av
    rb, b = bv
    val = _concrete(op, a, b)
    if val is None:
        return  # this concrete pair halts at runtime — nothing to bound
    abstract = _arith_result_range(op, ra, rb)
    # A successfully-executing concrete pair means the op does not
    # unconditionally halt on these ranges, so the kernel MUST give a range.
    assert abstract is not None, (
        f"{a} {op} {b} = {val} succeeded but kernel predicted an unconditional "
        f"halt for {ra.lo}..{ra.hi} {op} {rb.lo}..{rb.hi} (unsound)")
    lo, hi = _clamp_uint64(*abstract)
    assert lo <= val <= hi, (
        f"UNSOUND: {a} {op} {b} = {val} not in [{lo},{hi}] "
        f"(ranges {ra.lo}..{ra.hi} {op} {rb.lo}..{rb.hi})")


@settings(max_examples=300)
@given(_range_and_value())
def test_unary_not_range_contains_concrete(av):
    ra, a = av
    abstract = _unary_result_range("~", ra)
    assert abstract is not None
    lo, hi = _clamp_uint64(*abstract)
    val = _int_from_const(_fold_bitwise_not([_int_const(a)]))
    assert lo <= val <= hi, f"UNSOUND: ~{a} = {val} not in [{lo},{hi}] (range {ra.lo}..{ra.hi})"
