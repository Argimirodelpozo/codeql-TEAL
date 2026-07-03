"""Canonical SSA package.

Public API (call site idiom):

```python
from tealql.tealtools.ssa import SSAProgram, PySSA

prog = SSAProgram("contract.teal")   # a .teal file or a dir of them
# every existing analysis runs on prog.
```

Layout:
- :mod:`tealql.tealtools.ssa.models`  — pure data classes (SSAVar, Phi,
  Assignment, BasicBlock, Const, IntRange, Location,
  TealType) plus op-classification helpers (``_shuffle_mapping``,
  ``_TERMINATOR_OPS``, ``_OP_RANGE_SEEDS``, ``_CONST_BLOCK_REF_NAMES``,
  ``_STACK_SHUFFLE_OPS``).
- :mod:`tealql.tealtools.ssa.program`  — the :class:`SSAProgram` class. Its
  ``__init__`` does a structural pre-pass (CFG / AST / arity) then routes SSA
  construction through :class:`PySSA`; carries the constant-folding /
  range / liveness / materialize passes consumed by every analysis.
- :mod:`tealql.tealtools.ssa.ssa`      — the pure-Python :class:`PySSA`
  builder; :meth:`PySSA.build` returns an :class:`SSAProgram`
  wired up from PySSA-built structures (no separate wrap step).
"""
from __future__ import annotations

# AVM metadata (single home tealql.tealtools.avm) — re-exported here because
# the ssa layer is where most callers already look for them.
from ..avm import (
    _CONST_BLOCK_REF_NAMES,
    _OP_RANGE_SEEDS,
    _STACK_SHUFFLE_OPS,
    _TERMINATOR_OPS,
)

# Data classes + model-convention helpers from .models
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

# Operand -> constant resolution helpers from .operands
from .operands import const_bytes, const_byte_length, const_int, is_const, operand_const
from .producers import is_field_var, producing_op

# The SSAProgram class from .program
from .program import SSAProgram

# Pure-Python SSA builder + its internal data types from .ssa
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
