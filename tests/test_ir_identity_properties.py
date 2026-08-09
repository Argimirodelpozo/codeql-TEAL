"""Generated SSA -> pre-IR identity and operand agreement.

The real-corpus differential finds broad regressions but historically had to
join emitted intrinsics back to SSA by line.  These generated, stack-safe
reductions require every emitted intrinsic to retain its exact Assignment and
then compare operands through the public register-provenance bridge.
"""
from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from tealql.tealtools.lift import pre_ir  # noqa: E402
from tealql.tealtools.lift.lift import _Lifter  # noqa: E402
from tealql.tealtools.ssa import SSAProgram, SSAVar  # noqa: E402


_OPS = st.sampled_from(["+", "-", "*", "^", "|", "&", "==", "!=", "<", ">="])


@given(
    values=st.lists(st.integers(min_value=0, max_value=2**16),
                    min_size=1, max_size=10),
    ops=st.lists(_OPS, min_size=1, max_size=10),
)
@settings(max_examples=60, deadline=None)
def test_generated_integer_reductions_keep_exact_origins_and_operands(values, ops):
    body = ["#pragma version 10", "txn NumAppArgs"]
    for index, value in enumerate(values):
        body.extend((f"pushint {value}", ops[index % len(ops)]))
    body.append("return")
    prog = SSAProgram.from_text("\n".join(body) + "\n", name="generated.teal")
    lifter = _Lifter(prog)
    ir = lifter.build()

    emitted = 0
    for block in pre_ir.blocks(ir):
        for node in block.ops:
            intrinsic = (node.source if isinstance(node, pre_ir.Assignment)
                         and isinstance(node.source, pre_ir.Intrinsic)
                         else node.intrinsic
                         if isinstance(node, pre_ir.IntrinsicOp) else None)
            if intrinsic is None:
                continue
            assignment = intrinsic.origin
            assert assignment is not None
            assert prog.pyop_for_assignment(assignment) is not None
            assert assignment.op == intrinsic.op
            assert len(assignment.inputs) == len(intrinsic.args)
            emitted += 1

            for ssa_value, ir_value in zip(assignment.inputs, intrinsic.args):
                if isinstance(ir_value, pre_ir.Register):
                    assert ssa_value in lifter.register_sources[id(ir_value)]
                elif isinstance(ir_value, pre_ir.UInt64Constant):
                    assert isinstance(ssa_value, SSAVar)
                    const = ssa_value.const_value
                    assert const is not None and int(str(const.value), 0) == ir_value.value

    assert emitted >= len(values) + 1  # txn plus every reduction
