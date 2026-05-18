"""Functional / structured IR for TEAL programs.

Lifts the (CFG + SSA + control-tree) view into a small AST that
looks much like the source the contract was compiled from:

- Pure expression trees for value-producing ops.
- ``Let`` bindings for SSA values (defined once).
- ``Assign`` for materialized-phi vars (the few mutable globals the
  SSA layer's :meth:`SSAProgram.materialize_phis` introduces).
- Structured control flow: ``If`` / ``IfElse`` / ``Switch`` /
  ``Guard`` / ``Loop`` / ``Sequence``.
- ``Call`` for callsub with named args + results.
- ``Return`` / ``Halt`` for ``return`` / ``retsub`` / ``err``.

Inspired by the existing ``SSAProgram.functional()`` flat dump,
but reshaped into a tree the same way :mod:`tealtools.control_tree`
gave us a tree over the CFG.

See :mod:`tealtools.experimental.funcir.ir` for the dataclasses,
:mod:`tealtools.experimental.funcir.lifter` for the CFG→IR pass,
:mod:`tealtools.experimental.funcir.printer` for pretty printing.
"""

from .ir import (
    Expr, Lit, Ref, App, TupleExpr,
    Stmt, Block, Let, Assign, If, IfElse, Switch, Loop, Break,
    Guard, Call, Return, Halt, Assert, Label, Goto, IfGoto, Unstructured,
    Sub, Prog, walk,
)
from .lifter import lift
from .printer import pretty

__all__ = [
    "Expr", "Lit", "Ref", "App", "TupleExpr",
    "Stmt", "Block", "Let", "Assign", "If", "IfElse", "Switch", "Loop", "Break",
    "Guard", "Call", "Return", "Halt", "Assert",
    "Label", "Goto", "IfGoto", "Unstructured",
    "Sub", "Prog", "walk",
    "lift", "pretty",
]
