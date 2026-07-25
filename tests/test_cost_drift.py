"""Guard the AVM opcode COST table and the SIG arity table against puya's langspec.

``cost_analysis.OPCODE_COSTS`` and ``avm.SIG`` are hand-maintained SECOND sources
of truth beside puya's ``AVMOp`` model, and both had drifted:

* ``falcon_verify`` (AVM v12) was in NEITHER table — so ``op_arity`` returned
  ``(0, 0)`` and silently corrupted the stack simulation every later analysis is
  built on, and its 1700-unit cost was charged as 1;
* ``mimc`` / ``sumhash512`` / ``json_ref`` / ``base64_decode`` were charged 1
  while the module docstring claimed they carried "a representative constant",
  which broke the module's stated "sound over-approximation of the worst case"
  contract by three orders of magnitude for ``mimc``.

This is the sibling of ``test_avm_metadata_drift.py`` (which pins the op RESULT
TYPE tables): a new AVM version that adds or re-prices an opcode fails CI here
instead of quietly mis-modelling it.

Puya-gated: without puya installed there is no langspec to compare against.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from puya.ir.avm_ops import AVMOp

from tealql.tealtools import avm, cost_analysis

# Puya models these under an identifier where TEAL uses a symbol (`add` for `+`),
# or as pseudo-ops this project resolves from the const block. They are outside
# this test's reach by construction; kept explicit so a genuinely NEW opcode
# cannot hide in the gap.
_PUYA_ONLY_NAMES = frozenset({
    "add", "sub", "mul", "div_floor", "mod",
    "add_bytes", "sub_bytes", "mul_bytes", "div_floor_bytes", "mod_bytes",
    "lt", "gt", "lte", "gte", "eq", "neq", "not_", "and_", "or_",
    "lt_bytes", "gt_bytes", "lte_bytes", "gte_bytes", "eq_bytes", "neq_bytes",
    "bitwise_and", "bitwise_or", "bitwise_xor", "bitwise_not",
    "bitwise_and_bytes", "bitwise_or_bytes", "bitwise_xor_bytes",
    "bitwise_not_bytes",
    "len_", "global_",
})

# Height-dependent / dynamic-arity opcodes ``op_arity`` computes from the
# immediates rather than from :data:`avm.SIG`.
_DYNAMIC_ARITY = frozenset({
    "dig", "bury", "cover", "uncover", "popn", "dupn",
    "pushints", "pushbytess", "match", "switch",
    "frame_dig", "frame_bury", "callsub", "retsub", "proto",
})


def _teal_ops():
    """Puya ops that share a mnemonic with the TEAL source token."""
    return [op for op in AVMOp if op.code not in _PUYA_ONLY_NAMES]


def test_every_puya_opcode_has_a_sig_entry():
    """An opcode absent from :data:`avm.SIG` is modelled as ``(0, 0)`` — no
    stack effect at all — which corrupts the SSA reconstruction for every
    program using it. That must never happen silently."""
    missing = sorted(
        op.code for op in _teal_ops()
        if op.code not in avm.SIG and op.code not in _DYNAMIC_ARITY
    )
    assert not missing, (
        f"opcodes puya models but avm.SIG does not: {missing} — each is "
        "modelled with NO stack effect. Add them to SIG (and, if they are not "
        "cost 1, to cost_analysis.OPCODE_COSTS)."
    )


def test_fixed_opcode_costs_match_puya():
    """Every op puya prices with a FIXED cost must be priced identically here.

    Puya reports ``cost=None`` for the variable-cost ops (length- or
    curve-scaled); those are excluded and covered by
    :func:`test_variable_cost_ops_are_declared_inexact` instead."""
    mismatched = {}
    for op in _teal_ops():
        if op.cost is None:
            continue
        ours = cost_analysis.opcode_cost(op.code)
        if ours != op.cost:
            mismatched[op.code] = (ours, op.cost)
    assert not mismatched, (
        "OPCODE_COSTS disagrees with puya's langspec (ours, puya): "
        f"{mismatched}"
    )


def test_variable_cost_ops_are_declared_inexact():
    """Every op puya prices as VARIABLE (``cost=None``) and that this project
    charges more than the default must be declared in one of the "inexact"
    sets, so :func:`cost_analysis.length_scaled_ops_used` can warn about it.

    Without this the cost report presents a lower bound as if it were the
    documented worst-case over-approximation."""
    declared = cost_analysis.LENGTH_SCALED_OPS | cost_analysis.CURVE_SCALED_OPS
    undeclared = sorted(
        op.code for op in _teal_ops()
        if op.cost is None and op.code in cost_analysis.OPCODE_COSTS
        and op.code not in declared
    )
    assert not undeclared, (
        f"variable-cost ops priced with a constant but not declared inexact: "
        f"{undeclared} — add them to LENGTH_SCALED_OPS or CURVE_SCALED_OPS."
    )


def test_no_variable_cost_op_silently_defaults_to_one():
    """A variable-cost op that is in neither :data:`OPCODE_COSTS` nor the
    inexact sets is charged 1 with no signal at all — the exact hole
    ``mimc`` (10 + 550 per 32 bytes) fell through."""
    declared = cost_analysis.LENGTH_SCALED_OPS | cost_analysis.CURVE_SCALED_OPS
    silent = sorted(
        op.code for op in _teal_ops()
        if op.cost is None
        and op.code not in cost_analysis.OPCODE_COSTS
        and op.code not in declared
    )
    assert not silent, (
        f"variable-cost opcodes charged the default 1 with no signal: {silent}"
    )
