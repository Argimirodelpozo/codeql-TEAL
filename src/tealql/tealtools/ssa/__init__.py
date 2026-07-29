"""Canonical SSA package — ``SSAProgram("contract.teal")`` (a file or a dir of
them) builds, via the pure-Python :class:`PySSA`, the program every analysis
runs on: :mod:`.models` data classes, :mod:`.program` passes, :mod:`.ssa` builder.
"""
from __future__ import annotations

# AVM metadata lives in tealql.tealtools.avm; re-exported because the ssa layer
# is where most callers already look for it.
from ..avm import (
    _CONST_BLOCK_REF_NAMES,
    _OP_RANGE_SEEDS,
    _STACK_SHUFFLE_OPS,
    _TERMINATOR_OPS,
)

from .models import (
    Assignment,
    BasicBlock,
    Const,
    IntRange,
    Location,
    Operand,
    Phi,
    SSAVar,
    TealType,
    _shuffle_mapping,
    _canon_shuffle,
)

from .operands import (binary_operands, const_bytes, const_byte_length, const_int,
                       source_operands,
                       is_const, operand_const)
from .producers import is_field_var, producing_op

from .program import SSAProgram

from .ssa import (
    PyBlock,
    PyOp,
    PyPhi,
    PySSA,
    PyVar,
    STACK_MAX,
)

__all__ = [
    # Data classes
    "Assignment",
    "BasicBlock",
    "Const",
    "IntRange",
    "Location",
    "Operand",
    "Phi",
    "SSAVar",
    "TealType",
    # Op-classification helpers
    "_CONST_BLOCK_REF_NAMES",
    "_OP_RANGE_SEEDS",
    "_STACK_SHUFFLE_OPS",
    "_TERMINATOR_OPS",
    "_shuffle_mapping",
    "_canon_shuffle",
    # Operand -> constant resolution
    "const_bytes",
    "const_byte_length",
    "binary_operands",
    "source_operands",
    "const_int",
    "is_const",
    "operand_const",
    # Operand -> producing assignment
    "is_field_var",
    "producing_op",
    # SSAProgram + PySSA builder
    "SSAProgram",
    "PySSA",
    "PyVar",
    "PyPhi",
    "PyOp",
    "PyBlock",
    "STACK_MAX",
]
