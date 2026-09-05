"""Property-based SOUNDNESS of the IntRange arithmetic kernel.

The other range tests assert "computed bound == author-expected bound" — written
by the same author as the kernel, so they agree with a wrong bound. This checks
the property that actually matters: for any operand ranges, EVERY concrete input
pair that SUCCESSFULLY executes must produce a result inside the propagated range.
The concrete oracle is independent Python integer arithmetic, so an unsound bound
(too tight, an overflow that doesn't wrap, an off-by-one on ``%`` / ``<<``) — the
exact bug that would silently narrow an attacker-reachable value out of a guard —
fails here with a minimal counterexample.

A concrete pair that HALTS at runtime (uint64 overflow on ``+``/``*``, underflow
on ``-``, divide-by-zero) makes the reference return ``None``; there is no result
to bound, so it's skipped — matching the kernel's "reasons only about successful
executions" contract.
"""
from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings                       # noqa: E402
from hypothesis import strategies as st                      # noqa: E402

from tealql.tealtools.analysis._range_arithmetic import (    # noqa: E402
    _arith_result_range,
    _clamp_uint64,
    _unary_result_range,
)
from tealql.tealtools.ssa import IntRange                    # noqa: E402

MAX = 2 ** 64 - 1
_ARITH = ("+", "-", "*", "/", "%")
# AVM mnemonics: the kernel and the independent oracle both key on ``shl`` /
# ``shr``; spelled ``<<`` / ``>>`` every shift sample was vacuous (both None).
_BITWISE = ("&", "|", "^", "shl", "shr")


@st.composite
def _range_and_value(draw, max_value=MAX):
    """An ``IntRange`` over uint64 plus a concrete value inside it — so the
    concrete input is a member of the range by construction."""
    lo = draw(st.integers(min_value=0, max_value=max_value))
    hi = draw(st.integers(min_value=lo, max_value=max_value))
    v = draw(st.integers(min_value=lo, max_value=hi))
    return IntRange(lo, hi), v


def _concrete(op, a, b):
    # Independent mathematical reference: no production constant-folder calls.
    if op in {"/", "%"} and b == 0 or op in {"shl", "shr"} and b >= 64:
        return None
    if op == "+":
        value = a + b
    elif op == "-":
        value = a - b
    elif op == "*":
        value = a * b
    elif op == "/":
        value = a // b
    elif op == "%":
        value = a % b
    elif op == "&":
        value = a & b
    elif op == "|":
        value = a | b
    elif op == "^":
        value = a ^ b
    elif op == "shl":
        value = (a << b) & MAX
    elif op == "shr":
        value = a >> b
    else:
        raise AssertionError(op)
    return value if 0 <= value <= MAX else None


def _check_binary(op, av, bv):
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


@settings(max_examples=800)
@given(_range_and_value(), _range_and_value(), st.sampled_from(_ARITH + _BITWISE))
def test_binary_range_contains_every_concrete_result(av, bv, op):
    _check_binary(op, av, bv)


@settings(max_examples=400)
@given(_range_and_value(), _range_and_value(max_value=63), st.sampled_from(("shl", "shr")))
def test_shift_range_contains_every_concrete_result(av, bv, op):
    """Shifts need their own driver: a shift amount over 63 HALTS, so with the
    amount drawn over all of uint64 practically every shift sample was skipped
    (both kernel mutations of the shift rules survived the generic test).
    Drawing the amount in [0, 63] makes the samples execute."""
    _check_binary(op, av, bv)


@settings(max_examples=300)
@given(_range_and_value())
def test_unary_not_range_contains_concrete(av):
    ra, a = av
    abstract = _unary_result_range("~", ra)
    assert abstract is not None
    lo, hi = _clamp_uint64(*abstract)
    val = MAX ^ a
    assert lo <= val <= hi, f"UNSOUND: ~{a} = {val} not in [{lo},{hi}] (range {ra.lo}..{ra.hi})"
